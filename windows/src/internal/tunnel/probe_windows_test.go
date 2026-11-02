package tunnel

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestProbeUsesSelectedNodeAndVerifiesHTTPS(t *testing.T) {
	root := runtimeDir(t)
	var requests atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer origin.Close()
	// Only this VLESS fixture maps example.com on this random port back
	// to the test origin. A direct public request cannot reach this listener.
	port := freePort(t)
	var remote Session
	startFixture(t, &remote, root, object{"log": object{"level": "info"},
		"inbounds":  []object{{"type": "vless", "listen": "127.0.0.1", "listen_port": port, "users": []object{{"uuid": fakeUUID}}}},
		"outbounds": []object{{"type": "direct", "tag": "exit"}},
		"route":     object{"rules": []object{{"domain": "example.com", "action": "route", "outbound": "exit", "override_address": "127.0.0.1"}}}})
	p, _, err := parseNode(fmt.Sprintf("vless://%s@127.0.0.1:%d", fakeUUID, port))
	if err != nil {
		t.Fatal(err)
	}
	dst := fmt.Sprintf("https://example.com:%d/generate_204", origin.Listener.Addr().(*net.TCPAddr).Port)
	certs := x509.NewCertPool()
	certs.AddCert(origin.Certificate())
	d, err := probeHTTPS(context.Background(), root, p, dst, certs)
	if err != nil || d <= 0 || requests.Load() != 1 {
		t.Fatalf("probe through relay: %v %v", d, err)
	}
	if _, err := probeHTTPS(context.Background(), root, p, dst, x509.NewCertPool()); err == nil || requests.Load() != 1 {
		t.Fatal("unverified origin accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := probeHTTPS(ctx, root, p, dst, certs); err == nil {
		t.Fatal("canceled probe launched")
	}
}
