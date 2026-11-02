package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func runtimeDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(root, "runtime", "tunnel", "sing-box.exe")); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("required CI tunnel runtime missing")
		}
		t.Skip("run scripts/setup-tunnel.ps1 to verify against the pinned engine")
	}
	return root
}
func TestPinnedEngineAcceptsSupportedProfiles(t *testing.T) {
	root := runtimeDir(t)
	wg, err := WireGuard(sampleWG())
	if err != nil {
		t.Fatal(err)
	}
	profiles := []Profile{wg}
	for _, link := range samples() {
		p, _, err := parseNode(link)
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, p)
	}
	for _, p := range profiles {
		t.Run(p.Protocol, func(t *testing.T) {
			cfg, err := engineConfig(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(filepath.Join(root, "runtime", "tunnel", "sing-box.exe"), "check", "-c", "stdin")
			cmd.Stdin = bytes.NewReader(cfg)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("check: %s", out)
			}
		})
	}
}

func TestLibraryHidesSubscriptionAndProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "library.dat")
	secret := "example-secret-631"
	want := Library{Sources: []Source{{Name: "fixture", URL: "https://example.org/token/" + secret, Profiles: []Profile{{Name: "fixture", Link: secret}}}}}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte(secret)) {
		t.Fatal("cleartext library")
	}
	got, err := Load(path)
	if err != nil || got.Sources[0].URL != want.Sources[0].URL || got.Sources[0].Profiles[0].Link != secret {
		t.Fatal("library roundtrip failed")
	}
}
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}
func startFixture(t *testing.T, s *Session, root string, cfg object) {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.start(root, b); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Stop)
}

// The baseline test changes no routes and binds both fixture listeners to loopback.
// Only a disposable GitHub runner gets the explicit opt-in to exercise native TUN.
func TestLocalRelay(t *testing.T) { testRelay(t, false) }
func TestIsolatedTUNRelay(t *testing.T) {
	if os.Getenv("SORRYRKN_ISOLATED_TUN_TEST") != "1" || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("requires isolated hosted runner")
	}
	testRelay(t, true)
}
func testRelay(t *testing.T, useTUN bool) {
	root := runtimeDir(t)
	port := freePort(t)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "vless fixture reached") }))
	defer origin.Close()
	var remote Session
	startFixture(t, &remote, root, object{
		"log":       object{"level": "info"},
		"inbounds":  []object{{"type": "vless", "listen": "127.0.0.1", "listen_port": port, "users": []object{{"uuid": fakeUUID}}}},
		"outbounds": []object{{"type": "direct", "tag": "exit"}},
		"route":     object{"rules": []object{{"ip_cidr": "198.18.78.2/32", "action": "route", "outbound": "exit", "override_address": "127.0.0.1"}}},
	})
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?encryption=none", fakeUUID, port)
	p, _, err := parseNode(link)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := configFor(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{}
	defer transport.CloseIdleConnections()
	if useTUN {
		// Leave the runner's SSH/GitHub and DNS connectivity alone. Only the
		// otherwise unreachable fixture address is added to the native route table.
		tun := cfg["inbounds"].([]object)[0]
		tun["route_address"] = []string{"198.18.78.2/32"}
		tun["dns_mode"] = "disabled"
		tun["strict_route"] = false
		delete(tun, "route_exclude_address")
	} else {
		mixed := freePort(t)
		cfg["inbounds"] = []object{{"type": "socks", "listen": "127.0.0.1", "listen_port": mixed}}
		d, err := proxy.SOCKS5("tcp", "127.0.0.1:"+strconv.Itoa(mixed), nil, &net.Dialer{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		transport.DialContext = d.(proxy.ContextDialer).DialContext
	}
	var client Session
	startFixture(t, &client, root, cfg)
	if !client.Active() {
		t.Fatal("client exited during start")
	}
	hc := http.Client{Transport: transport, Timeout: 6 * time.Second}
	resp, err := hc.Get(strings.Replace(origin.URL, "127.0.0.1", "198.18.78.2", 1))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "vless fixture reached" {
		t.Fatalf("relay failed: %s, %v", body, err)
	}
	client.Stop()
	if client.Active() {
		t.Fatal("VPN still active after stop")
	}
}
