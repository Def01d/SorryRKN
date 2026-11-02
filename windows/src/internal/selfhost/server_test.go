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
	expected := "exec sudo -n sh -s -- status " + strings.Repeat("0", 32) + "\n"
	if entry != expected+strings.ReplaceAll(script, "\r\n", "\n") || strings.Contains(entry, server.Password) {
		t.Fatal("unexpected command or script")
	}
	if passwordUses.Load() != 1 {
		t.Fatal("expected one password authentication")
	}
}

func TestClientConfigCannotInjectDirectives(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	record := "SRKN1\tVPN\t" + key + "\t" + key + "\t" + key + "\t10.197.73.2\t51823\n"
	result, err := parseResult("2001:db8::1", InstallVPN, record)
	if err != nil || !strings.Contains(result.VPNConfig, "Endpoint = [2001:db8::1]:51823") {
		t.Fatalf("config: %v", err)
	}
	for _, bad := range []string{strings.Replace(record, "10.197.73.2", "8.8.8.8", 1), strings.Replace(record, "51823", "51823\nPostUp = cmd", 1), record + "another record\n"} {
		if _, err := parseResult("example.org", InstallVPN, bad); err == nil {
			t.Fatal("accepted injected or invalid profile")
		}
	}
	if _, err := (Server{Host: "example.org\nPostUp=cmd"}).endpoint(); err == nil {
		t.Fatal("accepted injected host")
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
