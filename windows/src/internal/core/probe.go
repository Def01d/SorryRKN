package core

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type Target struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Stage string `json:"stage"`
	Error string `json:"error,omitempty"`
}
type Check struct {
	Profile string   `json:"profile"`
	Targets []Target `json:"targets"`
	Seconds float64  `json:"seconds"`
}

func (c Check) Score() int {
	n := 0
	for _, t := range c.Targets {
		if t.OK {
			n++
		}
	}
	return n
}
func (c Check) Complete() bool { return len(c.Targets) == 2 && c.Score() == 2 }
func Probe(ctx context.Context, profile string) Check {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 3 * time.Second, ForceAttemptHTTP2: false}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 {
			return errors.New("too many redirects")
		}
		if r.URL.Scheme != "https" {
			return errors.New("insecure redirect")
		}
		return nil
	}}
	results := make(chan Target, 2)
	go func() {
		t := Target{Name: "YouTube", Stage: "HTTPS"}
		e := probeHTTP(ctx, client, "https://www.youtube.com/generate_204", nil)
		t.OK = e == nil
		if e != nil {
			t.Error = shortError(e)
		}
		results <- t
	}()
	go func() {
		t := Target{Name: "Discord", Stage: "API / WebSocket / CDN"}
		e := probeHTTP(ctx, client, "https://discord.com/api/v10/gateway", []byte("gateway.discord.gg"))
		if e == nil {
			e = probeHTTP(ctx, client, "https://cdn.discordapp.com/embed/avatars/0.png", []byte{137, 80, 78, 71})
		}
		if e == nil {
			e = GatewayHello(ctx)
		}
		t.OK = e == nil
		if e != nil {
			t.Error = shortError(e)
		}
		results <- t
	}()
	check := Check{Profile: profile}
	for i := 0; i < 2; i++ {
		check.Targets = append(check.Targets, <-results)
	}
	check.Seconds = time.Since(start).Seconds()
	return check
}
func probeHTTP(ctx context.Context, client *http.Client, url string, contains []byte) error {
	req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return e
	}
	req.Header.Set("User-Agent", "SorryRKN/"+Version)
	r, e := client.Do(req)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode < 200 || r.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 65536))
	if e != nil {
		return e
	}
	if len(contains) > 0 && !strings.Contains(string(b), string(contains)) {
		return errors.New("unexpected response")
	}
	return nil
}
func GatewayHello(ctx context.Context) error {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{ServerName: "gateway.discord.gg", MinVersion: tls.VersionTLS12}}
	conn, e := d.DialContext(ctx, "tcp", "gateway.discord.gg:443")
	if e != nil {
		return e
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	random := make([]byte, 16)
	if _, e = rand.Read(random); e != nil {
		return e
	}
	key := base64.StdEncoding.EncodeToString(random)
	fmt.Fprintf(conn, "GET /?v=10&encoding=json HTTP/1.1\r\nHost: gateway.discord.gg\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", key)
	reader := bufio.NewReader(conn)
	response, e := http.ReadResponse(reader, nil)
	if e != nil {
		return e
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if response.StatusCode != 101 || response.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		return errors.New("gateway upgrade failed")
	}
	for n := 0; n < 4; n++ {
		op, payload, e := ReadWSFrame(reader)
		if e != nil {
			return e
		}
		if op == 8 {
			return errors.New("gateway closed")
		}
		if op != 1 {
			continue
		}
		var hello struct {
			Op int `json:"op"`
			D  struct {
				Heartbeat int `json:"heartbeat_interval"`
			} `json:"d"`
		}
		if json.Unmarshal(payload, &hello) == nil && hello.Op == 10 && hello.D.Heartbeat > 0 {
			return nil
		}
	}
	return errors.New("gateway Hello missing")
}
func ReadWSFrame(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 2)
	if _, e := io.ReadFull(r, header); e != nil {
		return 0, nil, e
	}
	if header[0]&0x80 == 0 || header[1]&0x80 != 0 {
		return 0, nil, errors.New("unsupported gateway frame")
	}
	size := uint64(header[1] & 127)
	if size == 126 {
		b := make([]byte, 2)
		if _, e := io.ReadFull(r, b); e != nil {
			return 0, nil, e
		}
		size = uint64(binary.BigEndian.Uint16(b))
	}
	if size == 127 {
		b := make([]byte, 8)
		if _, e := io.ReadFull(r, b); e != nil {
			return 0, nil, e
		}
		size = binary.BigEndian.Uint64(b)
	}
	if size > 262144 {
		return 0, nil, errors.New("gateway frame too large")
	}
	b := make([]byte, int(size))
	_, e := io.ReadFull(r, b)
	return header[0] & 15, b, e
}
func shortError(e error) string {
	if errors.Is(e, context.DeadlineExceeded) {
		return "timeout"
	}
	if n, ok := e.(net.Error); ok && n.Timeout() {
		return "timeout"
	}
	s := e.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
