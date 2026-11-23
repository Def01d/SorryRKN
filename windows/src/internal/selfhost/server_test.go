package selfhost

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A real SSH handshake and session, with no access to the host shell.
func TestPinnedSSHSession(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	var passwordUses atomic.Int32
	cfg := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, pwd []byte) (*ssh.Permissions, error) {
		passwordUses.Add(1)
		if string(pwd) != "test-only" || meta.User() != "user" {
			return nil, fmt.Errorf("bad test login")
		}
		return nil, nil
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	transcript := make(chan string, 1)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(requests)
				for msg := range channels {
					ch, reqs, err := msg.Accept()
					if err != nil {
						return
					}
					for req := range reqs {
						if req.Type != "exec" {
							req.Reply(false, nil)
							continue
						}
						var exec struct{ Command string }
						ssh.Unmarshal(req.Payload, &exec)
						req.Reply(true, nil)
						program, err := io.ReadAll(ch)
						if err != nil {
							return
						}
						transcript <- exec.Command + "\n" + string(program)
						fmt.Fprintln(ch, "SRKN1\tSTATUS\tvpn:stopped\tsocks:missing")
						ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						ch.Close()
						break
					}
				}
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	server := Server{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, User: "user", Password: "test-only"}
	pin, err := ProbeFingerprint(ctx, server)
	if err != nil || pin != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("probe: %s %v", pin, err)
	}
	server.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	if _, err := Run(ctx, server, Status); err == nil {
		t.Fatal("accepted a changed host key")
	}
	if passwordUses.Load() != 0 {
		t.Fatal("sent credentials before authenticating the server")
	}
	server.Fingerprint = pin
	got, err := Run(ctx, server, Status)
	if err != nil || got.Status != "VPN: остановлен · SOCKS5: не установлен" {
		t.Fatalf("status: %v %v", got, err)
	}
	entry := <-transcript
	expected := "exec sudo -n sh -s -- status " + strings.Repeat("0", 32) + " 127.0.0.1\n"
	if entry != expected+strings.ReplaceAll(script, "\r\n", "\n") || strings.Contains(entry, server.Password) {
		t.Fatal("unexpected command or script")
	}
	if passwordUses.Load() != 1 {
		t.Fatal("expected one password authentication")
	}
}

func TestOnlyValidHTTPSProfiles(t *testing.T) {
	u := "naive+https://u" + strings.Repeat("1", 32) + ":" + strings.Repeat("a", 48) + "@sorryrkn.invalid:443/?sni=example.org"
	record := "SRKN1\tHTTPS\t" + u + "\n"
	r, err := parseResult("2001:db8::1", InstallHTTPS, record)
	if err != nil || !strings.Contains(r.NodeURL, "@[2001:db8::1]:443/") {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(record, "?sni=", "?ca=AAAA&sni=", 1), strings.Replace(record, "sorryrkn.invalid", "injected.invalid", 1), record + "extra record"} {
		if _, err := parseResult("example.org", InstallHTTPS, bad); err == nil {
			t.Fatal("accepted malformed HTTPS profile")
		}
	}
}

func TestExtendedProtocolsAndFleetParsing(t *testing.T) {
	mir := "SRKN1\tMIRAGE\tmirage://" + strings.Repeat("Q", 43) + "@sorryrkn.invalid:2096?sni=edge-telemetry.local&pin=" + strings.Repeat("a", 64) + "#Mirage"
	r, err := parseResult("203.0.113.5", InstallMirage, mir)
	if err != nil || !strings.Contains(r.NodeURL, "@203.0.113.5:2096?") {
		t.Fatalf("mirage parse: %+v %v", r, err)
	}

	hy := "SRKN1\tHY2\thy2://pass@sorryrkn.invalid:8443?sni=edge.cloudflare.com&spki=AAAA#Hy2"
	r, err = parseResult("203.0.113.5", InstallHy2, hy)
	if err != nil || !strings.Contains(r.NodeURL, "@203.0.113.5:8443?") {
		t.Fatalf("hy2 parse: %+v %v", r, err)
	}

	gr := "SRKN1\tGRPC\tvless://137001ca-1c37-4f48-a2d3-3d72253b051c@sorryrkn.invalid:2053?type=grpc&security=reality&pbk=pub&sni=www.microsoft.com#gRPC"
	r, err = parseResult("203.0.113.5", InstallGRPC, gr)
	if err != nil || !strings.Contains(r.NodeURL, "@203.0.113.5:2053?") {
		t.Fatalf("grpc parse: %+v %v", r, err)
	}

	sp := "SRKN1\tSOCKS-PUB\t10808\tsrkn_abcd\tsecret-pw-123"
	r, err = parseResult("203.0.113.5", InstallPublicSOCKS, sp)
	if err != nil || r.SOCKSPort != 10808 || !strings.Contains(r.TelegramURL, "tg://socks?") || !strings.Contains(r.PublicSOCKSURL, "@203.0.113.5:10808") {
		t.Fatalf("socks-pub parse: %+v %v", r, err)
	}

	fl := "SRKN1\tFLEET\thttps:running\tmirage:running\treality:stopped\thy2:missing\tgrpc:missing\tss2022:missing\tsocks_ssh:missing\tsocks_pub:running"
	r, err = parseResult("203.0.113.5", FleetStatus, fl)
	if err != nil || r.Fleet["mirage"] != "running" || r.Fleet["socks_pub"] != "running" {
		t.Fatalf("fleet parse: %+v %v", r, err)
	}

	pr, err := parseResult("203.0.113.5", PurgeAll, "SRKN1\tPURGED\tall")
	if err != nil || pr.Status == "" {
		t.Fatalf("purge parse: %+v %v", pr, err)
	}

	if _, err := parseResult("203.0.113.5", InstallMirage, strings.Replace(mir, "sorryrkn.invalid", "evil.example", 1)); err == nil {
		t.Fatal("accepted injected host in mirage profile")
	}
}
func TestCancellationInterruptsHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := ProbeFingerprint(ctx, Server{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port})
		done <- err
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled probe succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not cancel")
	}
}
