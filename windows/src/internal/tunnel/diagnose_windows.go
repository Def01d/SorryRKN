package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/net/websocket"
)

// Diagnose tests three independent paths. A public gateway Hello establishes
// WebSocket reachability, not account authentication or a successful voice call.
func Diagnose(ctx context.Context, appDir string, p Profile) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 24*time.Second)
	defer cancel()
	result := make([]string, 3)
	err := withProbe(ctx, appDir, p, func(dial proxy.ContextDialer, addr string, auth *proxy.Auth) error {
		var waits sync.WaitGroup
		waits.Add(3)
		go func() {
			defer waits.Done()
			elapsed, e := checkHTTPS(ctx, dial, probeURL, nil)
			if e != nil {
				result[0] = "HTTPS — запрос не прошёл"
			} else {
				result[0] = fmt.Sprintf("HTTPS — %d мс", elapsed.Milliseconds())
			}
		}()
		go func() {
			defer waits.Done()
			if checkDiscord(ctx, dial, "wss://gateway.discord.gg/?v=10&encoding=json", nil) != nil {
				result[1] = "Discord WebSocket — соединение не прошло"
			} else {
				result[1] = "Discord WebSocket — получен Hello"
			}
		}()
		go func() {
			defer waits.Done()
			u, _ := url.Parse(p.Link)
			if p.Protocol == "naive" && u.Query().Get("relay") == "" {
				result[2] = "UDP — старый TCP-профиль. Обновите HTTPS на VPS через «Свой сервер»."
				return
			}
			if checkSTUN(ctx, addr, auth, "stun.cloudflare.com", 3478) != nil {
				result[2] = "UDP/STUN — ответ не получен"
			} else {
				result[2] = "UDP/STUN — ответ получен"
			}
		}()
		waits.Wait()
		return nil
	})
	return result, err
}

// DiagnoseSystem exercises the same system route and DNS used by desktop apps.
// Call it only while our system VPN is active, alongside the per-node SOCKS test.
func DiagnoseSystem(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	results := make([]string, 3)
	var waits sync.WaitGroup
	waits.Add(3)
	go func() {
		defer waits.Done()
		elapsed, e := checkHTTPS(ctx, &net.Dialer{}, probeURL, nil)
		if e != nil {
			results[0] = "Системный HTTPS/DNS — запрос не прошёл"
		} else {
			results[0] = fmt.Sprintf("Системный HTTPS/DNS — %d мс", elapsed.Milliseconds())
		}
	}()
	go func() {
		defer waits.Done()
		if checkDiscord(ctx, &net.Dialer{}, "wss://gateway.discord.gg/?v=10&encoding=json", nil) != nil {
			results[1] = "Системный Discord WebSocket — соединение не прошло"
		} else {
			results[1] = "Системный Discord WebSocket — получен Hello"
		}
	}()
	go func() {
		defer waits.Done()
		conn, e := (&net.Dialer{}).DialContext(ctx, "udp", "stun.cloudflare.com:3478")
		if e == nil {
			defer conn.Close()
			deadline, _ := ctx.Deadline()
			conn.SetDeadline(deadline)
			request, err := stunRequest()
			e = err
			if e == nil {
				_, e = conn.Write(request)
			}
			if e == nil {
				buf := make([]byte, 65535)
				var n int
				n, e = conn.Read(buf)
				if e == nil {
					e = stunResponse(buf[:n], request)
				}
			}
		}
		if e != nil {
			results[2] = "Системный UDP/STUN — ответ не получен"
		} else {
			results[2] = "Системный UDP/STUN — ответ получен"
		}
	}()
	waits.Wait()
	return results
}

func checkDiscord(ctx context.Context, dial proxy.ContextDialer, target string, roots *tls.Config) error {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	config, err := websocket.NewConfig(target, "https://discord.com")
	if err != nil {
		return err
	}
	port := config.Location.Port()
	if port == "" {
		port = "443"
	}
	raw, err := dial.DialContext(ctx, "tcp", net.JoinHostPort(config.Location.Hostname(), port))
	if err != nil {
		return err
	}
	defer raw.Close()
	deadline, _ := ctx.Deadline()
	raw.SetDeadline(deadline)
	options := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.Location.Hostname()}
	if roots != nil {
		options.RootCAs = roots.RootCAs
	}
	secure := tls.Client(raw, options)
	if err = secure.HandshakeContext(ctx); err != nil {
		return err
	}
	conn, err := websocket.NewClient(config, secure)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.MaxPayloadBytes = 64 << 10
	var hello struct {
		Op int `json:"op"`
		D  struct {
			Heartbeat float64 `json:"heartbeat_interval"`
		} `json:"d"`
	}
	if err = websocket.JSON.Receive(conn, &hello); err != nil {
		return err
	}
	if hello.Op != 10 || hello.D.Heartbeat <= 0 {
		return errors.New("gateway did not send Hello")
	}
	return nil
}

// SOCKS5 UDP ASSOCIATE keeps its TCP control channel alive for the whole probe.
// Only the loopback engine talks to the destination. There is no direct fallback.
func socksUDP(ctx context.Context, addr string, auth *proxy.Auth) (*net.UDPConn, net.Conn, *net.UDPAddr, error) {
	fail := func(c net.Conn, e error) (*net.UDPConn, net.Conn, *net.UDPAddr, error) {
		if c != nil {
			c.Close()
		}
		return nil, nil, nil, e
	}
	control, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fail(nil, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	control.SetDeadline(deadline)
	greeting := []byte{5, 1, 0}
	if auth != nil {
		greeting[2] = 2
	}
	if _, err = control.Write(greeting); err != nil {
		return fail(control, err)
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(control, reply); err != nil {
		return fail(control, err)
	}
	if reply[0] != 5 || reply[1] != greeting[2] {
		return fail(control, errors.New("SOCKS method"))
	}
	if auth != nil {
		if len(auth.User) > 255 || len(auth.Password) > 255 {
			return fail(control, errors.New("SOCKS credentials"))
		}
		req := append([]byte{1, byte(len(auth.User))}, []byte(auth.User)...)
		req = append(req, byte(len(auth.Password)))
		req = append(req, []byte(auth.Password)...)
		if _, err = control.Write(req); err != nil {
			return fail(control, err)
		}
		if _, err = io.ReadFull(control, reply); err != nil {
			return fail(control, err)
		}
		if !bytes.Equal(reply, []byte{1, 0}) {
			return fail(control, errors.New("SOCKS authentication"))
		}
	}
	if _, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(control, err)
	}
	header := make([]byte, 4)
	if _, err = io.ReadFull(control, header); err != nil {
		return fail(control, err)
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return fail(control, errors.New("SOCKS UDP refused"))
	}
	size := 4
	if header[3] == 4 {
		size = 16
	} else if header[3] != 1 {
		return fail(control, errors.New("SOCKS UDP address"))
	}
	bound := make([]byte, size+2)
	if _, err = io.ReadFull(control, bound); err != nil {
		return fail(control, err)
	}
	ip := net.IP(bound[:size])
	if ip.IsUnspecified() {
		ip = net.ParseIP("127.0.0.1")
	}
	if !ip.IsLoopback() {
		return fail(control, errors.New("non-loopback UDP listener"))
	}
	remote := &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(bound[size:]))}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return fail(control, err)
	}
	udp.SetDeadline(deadline)
	return udp, control, remote, nil
}

func udpPacket(host string, port int, payload []byte) []byte {
	request := []byte{0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(request, 1)
			request = append(request, v4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else {
		request = append(request, 3, byte(len(host)))
		request = append(request, []byte(host)...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	return append(request, payload...)
}
func udpPayload(packet []byte) ([]byte, error) {
	if len(packet) < 4 || !bytes.Equal(packet[:3], []byte{0, 0, 0}) {
		return nil, errors.New("SOCKS UDP header")
	}
	size := 0
	switch packet[3] {
	case 1:
		size = 10
	case 4:
		size = 22
	case 3:
		if len(packet) >= 5 {
			size = 7 + int(packet[4])
		}
	}
	if size == 0 || len(packet) < size {
		return nil, errors.New("SOCKS UDP length")
	}
	return packet[size:], nil
}

func checkSTUN(ctx context.Context, addr string, auth *proxy.Auth, host string, port int) error {
	udp, control, remote, err := socksUDP(ctx, addr, auth)
	if err != nil {
		return err
	}
	defer control.Close()
	defer udp.Close()
	request, err := stunRequest()
	if err != nil {
		return err
	}
	if _, err = udp.WriteToUDP(udpPacket(host, port, request), remote); err != nil {
		return err
	}
	buffer := make([]byte, 65535)
	n, from, err := udp.ReadFromUDP(buffer)
	if err != nil {
		return err
	}
	if from.String() != remote.String() {
		return errors.New("unexpected UDP sender")
	}
	payload, err := udpPayload(buffer[:n])
	if err != nil {
		return err
	}
	return stunResponse(payload, request)
}

func stunRequest() ([]byte, error) {
	request := []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(request, nonce...), nil
}
func stunResponse(payload, request []byte) error {
	if len(payload) < 20 || len(request) != 20 || payload[0] != 1 || payload[1] != 1 || !bytes.Equal(payload[4:20], request[4:20]) || int(binary.BigEndian.Uint16(payload[2:4])) != len(payload)-20 {
		return errors.New("STUN binding response mismatch")
	}
	return nil
}
