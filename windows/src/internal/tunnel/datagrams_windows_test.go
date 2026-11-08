package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/net/websocket"
)

func TestHTTPSRelayTCPWebSocketAndUDP(t *testing.T) {
	root := runtimeDir(t)
	gateway, link := naiveFixture(t, freePort(t))
	gateway["tag"] = "gateway"
	payloadPort := freePort(t)
	var remote Session
	startFixture(t, &remote, root, object{"log": object{"level": "info"}, "inbounds": []object{gateway,
		{"type": "vless", "tag": "payload", "listen": "127.0.0.1", "listen_port": payloadPort, "users": []object{{"uuid": fakeUUID}}}},
		"outbounds": []object{{"type": "direct", "tag": "exit"}}, "route": object{"rules": []object{
			{"inbound": "gateway", "domain": "relay.sorryrkn.invalid", "action": "route", "outbound": "exit", "override_address": "127.0.0.1", "override_port": payloadPort},
			{"inbound": "payload", "domain": "example.com", "action": "route", "outbound": "exit", "override_address": "127.0.0.1"},
			{"inbound": "payload", "ip_cidr": "198.18.78.2/32", "action": "route", "outbound": "exit", "override_address": "127.0.0.1"},
			{"action": "reject"}}}})
	p, _, err := parseNode(link + "&relay=" + fakeUUID)
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			websocket.Handler(func(c *websocket.Conn) {
				defer c.Close()
				websocket.JSON.Send(c, map[string]any{"op": 10, "d": map[string]int{"heartbeat_interval": 45000}})
			}).ServeHTTP(w, r)
			return
		}
		w.WriteHeader(204)
	}))
	defer origin.Close()
	certs := x509.NewCertPool()
	certs.AddCert(origin.Certificate())
	public := strings.Replace(origin.URL, "127.0.0.1", "example.com", 1)
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, e := echo.ReadFromUDP(buf)
			if e != nil {
				return
			}
			echo.WriteToUDP(buf[:n], from)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = withProbe(ctx, root, p, func(dial proxy.ContextDialer, addr string, auth *proxy.Auth) error {
		if _, err := checkHTTPS(ctx, dial, public, certs); err != nil {
			return fmt.Errorf("HTTPS: %w", err)
		}
		if err := checkDiscord(ctx, dial, strings.Replace(public, "https://", "wss://", 1)+"/ws", &tls.Config{RootCAs: certs}); err != nil {
			return fmt.Errorf("WebSocket: %w", err)
		}
		udp, control, bound, err := socksUDP(ctx, addr, auth)
		if err != nil {
			return err
		}
		defer control.Close()
		defer udp.Close()
		port := echo.LocalAddr().(*net.UDPAddr).Port
		for i := 0; i < 100; i++ {
			// Small voice-sized frames and datagrams near the tunnel MTU.
			payload := bytes.Repeat([]byte{byte(i)}, []int{64, 160, 1000, 1300}[i%4])
			if _, err = udp.WriteToUDP(udpPacket("198.18.78.2", port, payload), bound); err != nil {
				return err
			}
			buf := make([]byte, 65535)
			n, _, err := udp.ReadFromUDP(buf)
			if err != nil {
				return fmt.Errorf("UDP packet %d: %w", i, err)
			}
			got, err := udpPayload(buf[:n])
			if err != nil || !bytes.Equal(payload, got) {
				return fmt.Errorf("UDP packet %d corrupted", i)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// No advertised relay may be silently interpreted as UDP support.
	if _, _, err := parseNode(link + "&relay=invalid"); err == nil {
		t.Fatal("accepted invalid relay")
	}
}
