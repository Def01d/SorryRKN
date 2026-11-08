package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

const probeURL = "https://www.gstatic.com/generate_204"

// Probe measures a fixed TLS-verified request through this node. Its temporary
// listener is authenticated, loopback-only, and creates no system routes.
func Probe(ctx context.Context, appDir string, p Profile) (time.Duration, error) {
	return probeHTTPS(ctx, appDir, p, probeURL, nil)
}
func probeHTTPS(ctx context.Context, appDir string, p Profile, target string, roots *x509.CertPool) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, 18*time.Second)
	defer cancel()
	var elapsed time.Duration
	err := withProbe(ctx, appDir, p, func(dial proxy.ContextDialer, _ string, _ *proxy.Auth) error {
		var err error
		elapsed, err = checkHTTPS(ctx, dial, target, roots)
		return err
	})
	return elapsed, err
}

func withProbe(ctx context.Context, appDir string, p Profile, check func(proxy.ContextDialer, string, *proxy.Auth) error) error {
	cfg, err := configFor(ctx, p)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("не удалось зарезервировать локальный порт проверки")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	addr := listener.Addr().String()
	listener.Close()
	var nonce [24]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return errors.New("не удалось создать пароль проверки")
	}
	auth := proxy.Auth{User: "check", Password: hex.EncodeToString(nonce[:])}
	cfg["inbounds"] = []object{{"type": "socks", "listen": "127.0.0.1", "listen_port": port, "users": []object{{"username": auth.User, "password": auth.Password}}}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return errors.New("не удалось создать конфигурацию проверки")
	}
	defer clear(raw)
	var session Session
	if err = session.startContext(ctx, appDir, raw); err != nil {
		return err
	}
	defer session.Stop()
	dial, err := proxy.SOCKS5("tcp", addr, &auth, &net.Dialer{Timeout: 4 * time.Second})
	if err != nil {
		return errors.New("не удалось создать соединение проверки")
	}
	return check(dial.(proxy.ContextDialer), addr, &auth)
}

func checkHTTPS(ctx context.Context, dial proxy.ContextDialer, target string, roots *x509.CertPool) (time.Duration, error) {
	transport := &http.Transport{DialContext: dial.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DisableKeepAlives: true, ForceAttemptHTTP2: true, MaxResponseHeaderBytes: 32 << 10}
	defer transport.CloseIdleConnections()
	client := http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, errors.New("неверный адрес проверки")
	}
	req.Header.Set("Accept-Encoding", "identity")
	begin := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, errors.New("узел не доставил проверочный HTTPS-запрос")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return 0, fmt.Errorf("проверочный адрес ответил HTTP %d", resp.StatusCode)
	}
	if resp.TLS == nil || len(resp.TLS.VerifiedChains) == 0 {
		return 0, errors.New("сертификат проверочного адреса не подтверждён")
	}
	return time.Since(begin), nil
}
