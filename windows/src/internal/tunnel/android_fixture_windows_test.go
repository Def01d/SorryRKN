package tunnel

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Optional loopback peer for HTTPSRelayDeviceChecks on the Android emulator.
// It never creates an interface or changes host network configuration.
func TestAndroidHTTPSFixture(t *testing.T) {
	dir := os.Getenv("SORRYRKN_ANDROID_FIXTURE_DIR")
	if dir == "" {
		t.Skip("explicit emulator fixture only")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("absolute fixture directory required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	root := runtimeDir(t)
	gateway, link := naiveFixture(t, freePort(t))
	gateway["tag"] = "gateway"
	payloadPort := freePort(t)
	var peer Session
	startFixture(t, &peer, root, object{"log": object{"level": "info"}, "inbounds": []object{gateway,
		{"type": "vless", "tag": "payload", "listen": "127.0.0.1", "listen_port": payloadPort, "users": []object{{"uuid": fakeUUID}}}},
		"outbounds": []object{{"type": "direct", "tag": "exit"}}, "route": object{"rules": []object{
			{"inbound": "gateway", "domain": "relay.sorryrkn.invalid", "action": "route", "outbound": "exit", "override_address": "127.0.0.1", "override_port": payloadPort},
			{"inbound": "payload", "ip_cidr": "10.0.2.2/32", "port_range": []string{"18888:18889"}, "action": "route", "outbound": "exit", "override_address": "127.0.0.1"},
			{"action": "reject"}}}})
	tcp, err := net.Listen("tcp4", "127.0.0.1:18888")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			c, e := tcp.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(15 * time.Second))
				data := make([]byte, 128<<10)
				if _, e := io.ReadFull(c, data); e != nil {
					return
				}
				for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
					data[i], data[j] = data[j], data[i]
				}
				io.Copy(c, bytes.NewReader(data))
			}()
		}
	}()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:18889")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, from, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udp.WriteTo(b[:n], from)
		}
	}()
	link = strings.Replace(link, "@127.0.0.1:", "@10.0.2.2:", 1) + "&relay=" + fakeUUID
	data, _ := json.Marshal(map[string]string{"https": link})
	if err = os.WriteFile(filepath.Join(dir, "profile.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("Emulator HTTPS fixture READY")
	end := time.Now().Add(10 * time.Minute)
	for time.Now().Before(end) {
		if _, e := os.Stat(filepath.Join(dir, "stop")); e == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("fixture timed out waiting for emulator")
}
