//go:build !clientonly

package mirage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestURIRoundTripAndValidation(t *testing.T) {
	secB64, pinHex, _, _, err := GenerateCredentials("edge.example.com")
	if err != nil {
		t.Fatalf("GenerateCredentials: %v", err)
	}
	raw := fmt.Sprintf("mirage://%s@203.0.113.10:443?sni=edge.example.com&pin=%s&cover=cdn.example.com&fp=chrome&chaff=1&mtu=1360#My+Mirage", secB64, pinHex)
	cfg, err := ParseURI(raw)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if cfg.ServerHost != "203.0.113.10" || cfg.ServerPort != 443 || cfg.SNI != "edge.example.com" || cfg.CoverHost != "cdn.example.com" || !cfg.Chaff {
		t.Fatalf("unexpected parsed config: %+v", cfg)
	}
	roundTrip, err := ParseURI(cfg.URI())
	if err != nil {
		t.Fatalf("roundtrip ParseURI: %v", err)
	}
	if roundTrip.Secret != cfg.Secret || roundTrip.PinSHA256 != cfg.PinSHA256 {
		t.Fatal("roundtrip keys mismatch")
	}

	badURIs := []string{
		"vless://uuid@example.com:443",
		"mirage://example.com:443?pin=" + pinHex,
		"mirage://short@example.com:443?pin=" + pinHex,
		fmt.Sprintf("mirage://%s@example.com:443?pin=deadbeef", secB64),
	}
	for _, b := range badURIs {
		if _, err := ParseURI(b); err == nil {
			t.Fatalf("expected error for invalid URI %q", b)
		}
	}
}

func TestCovertKnockReplayAndSkew(t *testing.T) {
	var psk [SecretSize]byte
	_, _ = rand.Read(psk[:])
	var eph [32]byte
	_, _ = rand.Read(eph[:])

	now := time.Now()
	tok, _, err := buildKnockToken(psk, eph, now)
	if err != nil {
		t.Fatalf("buildKnockToken: %v", err)
	}
	if _, ok := verifyKnockToken(psk, tok, now.Add(45*time.Second)); !ok {
		t.Fatal("expected token within skew window to verify")
	}
	if _, ok := verifyKnockToken(psk, tok, now.Add(MaxClockSkew+10*time.Second)); ok {
		t.Fatal("expected expired token outside skew window to fail")
	}
	wrongKey := psk
	wrongKey[0] ^= 0xFF
	if _, ok := verifyKnockToken(wrongKey, tok, now); ok {
		t.Fatal("expected wrong PSK verification to fail")
	}
}

func startTestServer(t *testing.T, allowPrivate bool) (*Server, *ClientConfig, string) {
	t.Helper()
	secB64, pinHex, certPEM, keyPEM, err := GenerateCredentials("localhost")
	if err != nil {
		t.Fatalf("GenerateCredentials: %v", err)
	}
	sec, _ := DecodeSecret(secB64)
	pin, _, _ := DecodePin(pinHex)

	srv, err := NewServer(ServerConfig{
		ListenAddr:          "127.0.0.1:0",
		Secret:              sec,
		CertPEM:             certPEM,
		KeyPEM:              keyPEM,
		Chaff:               true,
		AllowPrivateTargets: allowPrivate,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	addr, err := srv.Start(context.Background())
	if err != nil {
		t.Fatalf("Server.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	_, portStr, _ := net.SplitHostPort(addr)
	portNum, _ := strconv.Atoi(portStr)
	cfg := &ClientConfig{
		Name:        "Test",
		ServerHost:  "127.0.0.1",
		ServerPort:  uint16(portNum),
		SNI:         "localhost",
		CoverHost:   "localhost",
		PinSHA256:   pin,
		PinHex:      pinHex,
		Secret:      sec,
		Fingerprint: "chrome",
		Chaff:       true,
		MTU:         DefaultMTU,
		ListenAddr:  "127.0.0.1:0",
	}
	return srv, cfg, addr
}

func TestActiveProbeCoverHTMLAndReplayDefense(t *testing.T) {
	_, cfg, srvAddr := startTestServer(t, true)

	// 1. Plain HTTPS GET probe gets benign cover HTML with no X-Session-Token.
	hc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := hc.Get("https://" + srvAddr + "/")
	if err != nil {
		t.Fatalf("probe GET: %v", err)
	}
	bodyBytes, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Session-Token") != "" {
		t.Fatalf("unexpected probe response: status=%d hdr=%v", resp.StatusCode, resp.Header)
	}
	if !strings.Contains(string(bodyBytes), "API Telemetry Endpoint") {
		t.Fatalf("missing cover page HTML: %s", string(bodyBytes))
	}

	// 2. Capture and replay the exact same POST _sid cookie: 1st succeeds, 2nd gets cover HTML.
	var eph [32]byte
	_, _ = rand.Read(eph[:])
	tok, _, _ := buildKnockToken(cfg.Secret, eph, time.Now())

	sendRawKnock := func() (*http.Response, string) {
		conn, err := tls.Dial("tcp", srvAddr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("tls.Dial: %v", err)
		}
		defer func() { _ = conn.Close() }()
		rawReq := fmt.Sprintf("POST /api/v1/telemetry/events HTTP/1.1\r\nHost: localhost\r\nCookie: _sid=%s\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}", tok)
		_, _ = io.WriteString(conn, rawReq)
		r, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("ReadResponse: %v", err)
		}
		return r, r.Header.Get("X-Session-Token")
	}

	r1, tok1 := sendRawKnock()
	if r1.StatusCode != http.StatusOK || tok1 == "" {
		t.Fatalf("expected 1st authentic knock to upgrade, got status=%d tok=%q", r1.StatusCode, tok1)
	}
	r2, tok2 := sendRawKnock()
	if tok2 != "" {
		t.Fatalf("expected replayed knock to be rejected with cover page, got X-Session-Token=%q", tok2)
	}
	replayedBody, _ := io.ReadAll(r2.Body)
	_ = r2.Body.Close()
	if !strings.Contains(string(replayedBody), "API Telemetry Endpoint") {
		t.Fatalf("expected replayed knock to receive cover page, got %q", string(replayedBody))
	}
}

func TestPinMismatchBlocksBeforeKnock(t *testing.T) {
	_, cfg, _ := startTestServer(t, true)
	cfg.PinSHA256[0] ^= 0xFF
	cli, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = cli.dialManagedCarrier(context.Background())
	if err == nil || !strings.Contains(err.Error(), "отпечаток TLS-сертификата") {
		t.Fatalf("expected MITM pin mismatch error, got: %v", err)
	}
}

func TestTCPConcurrentE2EAndAuth(t *testing.T) {
	_, cfg, _ := startTestServer(t, true)
	cfg.AuthUser = "mirage_user"
	cfg.AuthPass = "s3cr3t_pass"

	cli, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	socksAddr, err := cli.Start(context.Background())
	if err != nil {
		t.Fatalf("Client.Start: %v", err)
	}
	defer func() { _ = cli.Close() }()

	// Upstream HTTP server on loopback.
	payload := bytes.Repeat([]byte("SRKN-MIRAGE-DATA-BLOCK-0123456789!"), 4000) // ~136 KB
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer ts.Close()

	// Verify SOCKS5 rejects wrong credentials.
	if err := dialSOCKS5AndCheck(socksAddr, "wrong", "wrong", "127.0.0.1", 80); err == nil {
		t.Fatal("expected SOCKS5 auth rejection")
	}

	// Concurrent downloads over multiplexed Mirage carrier with SOCKS5 auth.
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	_, targetAddr, _ := strings.Cut(ts.URL, "http://")
	thost, tportStr, _ := net.SplitHostPort(targetAddr)
	tport, _ := strconv.Atoi(tportStr)

	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dialSOCKS5Connect(socksAddr, cfg.AuthUser, cfg.AuthPass, thost, uint16(tport))
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = conn.Close() }()
			_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetAddr)
			if err != nil {
				errs <- err
				return
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.CloseWrite() // Exercises half-close FrameFIN path!
			}
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				errs <- err
				return
			}
			got, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, payload) {
				errs <- fmt.Errorf("body mismatch: got %d bytes want %d", len(got), len(payload))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent stream failed: %v", e)
	}
}

func TestUDPEchoOverMirageSOCKS5(t *testing.T) {
	_, cfg, _ := startTestServer(t, true)
	cli, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	socksAddr, err := cli.Start(context.Background())
	if err != nil {
		t.Fatalf("Client.Start: %v", err)
	}
	defer func() { _ = cli.Close() }()

	// UDP echo upstream.
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer func() { _ = echoConn.Close() }()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echoConn.WriteToUDP(append([]byte("ECHO:"), buf[:n]...), addr)
		}
	}()

	ctrl, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5: %v", err)
	}
	defer func() { _ = ctrl.Close() }()
	_, _ = ctrl.Write([]byte{0x05, 0x01, 0x00})
	var authRep [2]byte
	if _, err := io.ReadFull(ctrl, authRep[:]); err != nil || authRep[1] != 0x00 {
		t.Fatalf("auth reply: %v %x", err, authRep)
	}
	_, _ = ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	var rep [10]byte
	if _, err := io.ReadFull(ctrl, rep[:]); err != nil || rep[1] != 0x00 {
		t.Fatalf("udp associate reply: %v %x", err, rep)
	}
	relayPort := int(binary.BigEndian.Uint16(rep[8:10]))
	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IP(rep[4:8]), Port: relayPort})
	if err != nil {
		t.Fatalf("DialUDP relay: %v", err)
	}
	defer func() { _ = uc.Close() }()

	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)
	msg := []byte("hello-mirage-udp")
	pkt := make([]byte, 10+len(msg))
	pkt[3] = 0x01
	copy(pkt[4:8], echoAddr.IP.To4())
	binary.BigEndian.PutUint16(pkt[8:10], uint16(echoAddr.Port))
	copy(pkt[10:], msg)
	if _, err := uc.Write(pkt); err != nil {
		t.Fatalf("UDP write: %v", err)
	}
	_ = uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	rbuf := make([]byte, 2048)
	n, err := uc.Read(rbuf)
	if err != nil {
		t.Fatalf("UDP read: %v", err)
	}
	if n <= 10 || string(rbuf[10:n]) != "ECHO:hello-mirage-udp" {
		t.Fatalf("unexpected UDP echo payload: %q", string(rbuf[10:n]))
	}
}

func TestSSRFBlocksPrivateTargetsByDefault(t *testing.T) {
	_, cfg, _ := startTestServer(t, false) // AllowPrivateTargets = false
	cli, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	socksAddr, err := cli.Start(context.Background())
	if err != nil {
		t.Fatalf("Client.Start: %v", err)
	}
	defer func() { _ = cli.Close() }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	if _, err := dialSOCKS5Connect(socksAddr, "", "", "127.0.0.1", uint16(port)); err == nil {
		t.Fatal("expected SSRF guard to block loopback target")
	}
}

func TestCarrierRotationSeamless(t *testing.T) {
	_, cfg, _ := startTestServer(t, true)
	cli, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = cli.Close() }()

	// Acquire initial carrier and force its byte limit low to trigger rotation on next acquire.
	c1, err := cli.acquireCarrier(context.Background())
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	cli.poolMu.Lock()
	cli.active.byteLimit = 0
	cli.poolMu.Unlock()

	// Next acquire must retire c1 cleanly and dial a distinct c2 carrier.
	c2, err := cli.acquireCarrier(context.Background())
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	if c1 == c2 {
		t.Fatal("expected new carrier after rotation threshold")
	}
	if !c1.IsRetired() {
		t.Fatal("expected previous carrier to be marked retired")
	}
	// Open stream on c2 works cleanly while c1 reaps once idle.
	cli.scheduleReap()
	select {
	case <-c1.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("expected idle retired carrier c1 to be reaped")
	}
}

func dialSOCKS5AndCheck(socksAddr, user, pass, host string, port uint16) error {
	c, err := dialSOCKS5Connect(socksAddr, user, pass, host, port)
	if err == nil {
		_ = c.Close()
	}
	return err
}

func dialSOCKS5Connect(socksAddr, user, pass, host string, port uint16) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if user != "" {
		_, _ = c.Write([]byte{0x05, 0x01, 0x02})
	} else {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	}
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil {
		_ = c.Close()
		return nil, err
	}
	if m[1] == 0xFF {
		_ = c.Close()
		return nil, errors.New("SOCKS5 method rejected")
	}
	if m[1] == 0x02 {
		buf := make([]byte, 0, 3+len(user)+len(pass))
		buf = append(buf, 0x01, byte(len(user)))
		buf = append(buf, user...)
		buf = append(buf, byte(len(pass)))
		buf = append(buf, pass...)
		_, _ = c.Write(buf)
		var ar [2]byte
		if _, err := io.ReadFull(c, ar[:]); err != nil || ar[1] != 0x00 {
			_ = c.Close()
			return nil, errors.New("SOCKS5 auth failed")
		}
	}
	ip := net.ParseIP(host).To4()
	req := make([]byte, 0, 32)
	if ip != nil {
		req = append(req, 0x05, 0x01, 0x00, 0x01)
		req = append(req, ip...)
	} else {
		req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	req = append(req, pb[:]...)
	_, _ = c.Write(req)

	var rep [4]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil || rep[1] != 0x00 {
		_ = c.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed: %v code=%d", err, rep[1])
	}
	switch rep[3] {
	case 0x01:
		var d [6]byte
		_, _ = io.ReadFull(c, d[:])
	case 0x04:
		var d [18]byte
		_, _ = io.ReadFull(c, d[:])
	}
	return c, nil
}
