//go:build !clientonly

package mirage

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ServerConfig configures the SRKN-Mirage server daemon.
type ServerConfig struct {
	ListenAddr          string
	Secret              [SecretSize]byte
	CertFile            string
	KeyFile             string
	CertPEM             []byte
	KeyPEM              []byte
	Chaff               bool
	AllowPrivateTargets bool
}

// Server accepts TLS 1.3 connections, serves benign HTML to unauthenticated probes,
// and upgrades covertly authenticated clients to multiplexed Mirage carriers.
type Server struct {
	cfg    ServerConfig
	tlsCfg *tls.Config
	replay *replayGuard

	ctx    context.Context
	cancel context.CancelFunc

	lnMu sync.Mutex
	ln   net.Listener

	wg sync.WaitGroup
}

// NewServer validates cfg and loads TLS certificates.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":443"
	}
	var cert tls.Certificate
	var err error
	switch {
	case len(cfg.CertPEM) > 0 && len(cfg.KeyPEM) > 0:
		cert, err = tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
	case cfg.CertFile != "" && cfg.KeyFile != "":
		cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	default:
		return nil, errors.New("не указан TLS-сертификат и приватный ключ для сервера mirage")
	}
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки TLS-сертификата mirage: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg: cfg,
		tlsCfg: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"http/1.1"},
		},
		replay: newReplayGuard(),
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start opens the TLS listener and accepts incoming clients asynchronously.
func (s *Server) Start(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return "", err
	}
	s.lnMu.Lock()
	s.ln = ln
	s.lnMu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.ctx.Done():
		}
	}()

	s.wg.Add(1)
	go s.acceptLoop(ln)
	return ln.Addr().String(), nil
}

// Serve runs the Mirage server until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	if _, err := s.Start(ctx); err != nil {
		return err
	}
	s.wg.Wait()
	return nil
}

// Close shuts down the listener and active server carriers.
func (s *Server) Close() error {
	s.cancel()
	s.lnMu.Lock()
	ln := s.ln
	s.ln = nil
	s.lnMu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	s.wg.Wait()
	return nil
}

func (s *Server) acceptLoop(ln net.Listener) {
	defer s.wg.Done()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(nc net.Conn) {
			defer s.wg.Done()
			s.handleConn(nc)
		}(raw)
	}
}

func (s *Server) handleConn(raw net.Conn) {
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	tlsConn := tls.Server(raw, s.tlsCfg)
	hsCtx, hsCancel := context.WithTimeout(s.ctx, 10*time.Second)
	err := tlsConn.HandshakeContext(hsCtx)
	hsCancel()
	if err != nil {
		_ = tlsConn.Close()
		return
	}

	_ = tlsConn.SetDeadline(time.Now().Add(12 * time.Second))
	br := bufio.NewReaderSize(tlsConn, 4096)
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = tlsConn.Close()
		return
	}
	if req.ContentLength > 0 && req.ContentLength <= 16*1024 {
		_, _ = io.CopyN(io.Discard, req.Body, req.ContentLength)
	}
	_ = req.Body.Close()

	kd, authorized := s.authorizeKnock(req)
	if !authorized {
		s.serveCoverPage(tlsConn)
		return
	}

	srvPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		s.serveCoverPage(tlsConn)
		return
	}
	peerPub, err := ecdh.X25519().NewPublicKey(kd.ClientEphPub[:])
	if err != nil {
		s.serveCoverPage(tlsConn)
		return
	}
	shared, err := srvPriv.ECDH(peerPub)
	if err != nil {
		s.serveCoverPage(tlsConn)
		return
	}
	var srvPub [32]byte
	copy(srvPub[:], srvPriv.PublicKey().Bytes())

	ackTok, srvNonce, err := buildServerAck(s.cfg.Secret, kd.ClientEphPub, kd.ClientNonce, srvPub)
	if err != nil {
		_ = tlsConn.Close()
		return
	}
	keys := deriveSessionKeys(shared, s.cfg.Secret, kd.ClientNonce, srvNonce)

	resp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Server: nginx\r\n"+
			"Content-Type: application/octet-stream\r\n"+
			"Cache-Control: no-store\r\n"+
			"Connection: keep-alive\r\n"+
			"X-Session-Token: %s\r\n\r\n",
		ackTok,
	)
	if _, err := io.WriteString(tlsConn, resp); err != nil {
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	bc := &bufferedConn{Conn: tlsConn, br: br}
	codec, err := newWireCodec(bc, false, keys, s.cfg.Chaff)
	if err != nil {
		_ = tlsConn.Close()
		return
	}

	hooks := carrierHooks{
		DialTCP: s.dialGuardedTCP,
		OpenUDP: s.openGuardedUDP,
	}
	mux := newMuxCarrier(s.ctx, codec, false, hooks, s.cfg.Chaff, nil)
	mux.Wait()
}

func (s *Server) authorizeKnock(req *http.Request) (knockData, bool) {
	if req.Method != http.MethodPost || req.URL == nil || req.URL.Path != "/api/v1/telemetry/events" {
		return knockData{}, false
	}
	cookie, err := req.Cookie("_sid")
	if err != nil || cookie.Value == "" {
		return knockData{}, false
	}
	now := time.Now()
	kd, ok := verifyKnockToken(s.cfg.Secret, cookie.Value, now)
	if !ok {
		return knockData{}, false
	}
	if !s.replay.TryConsume(kd.ReplayID, now) {
		return knockData{}, false
	}
	return kd, true
}

func (s *Server) serveCoverPage(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
	resp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Server: nginx\r\n"+
			"Date: %s\r\n"+
			"Content-Type: text/html; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n%s",
		time.Now().UTC().Format(http.TimeFormat),
		len(coverHTMLPage),
		coverHTMLPage,
	)
	_, _ = io.WriteString(conn, resp)
}

func (s *Server) dialGuardedTCP(ctx context.Context, _ byte, host string, port uint16) (net.Conn, error) {
	if port == 0 {
		return nil, errors.New("неверный целевой порт")
	}
	ips, err := s.resolveSafeTarget(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	var lastErr error
	for _, ip := range ips {
		c, derr := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(int(port))))
		if derr == nil {
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
			return c, nil
		}
		lastErr = derr
	}
	if lastErr == nil {
		lastErr = errors.New("целевой узел недоступен")
	}
	return nil, lastErr
}

type serverUDPRelay struct {
	server *Server
	conn   *net.UDPConn
	reply  func(atyp byte, host string, port uint16, data []byte) error
}

func (r *serverUDPRelay) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		var atyp byte = AddrIPv6
		if src.IP.To4() != nil {
			atyp = AddrIPv4
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if err := r.reply(atyp, src.IP.String(), uint16(src.Port), pkt); err != nil {
			return
		}
	}
}

func (r *serverUDPRelay) Send(_ byte, host string, port uint16, data []byte) error {
	if port == 0 {
		return errors.New("неверный UDP-порт")
	}
	ctx, cancel := context.WithTimeout(r.server.ctx, 4*time.Second)
	ips, err := r.server.resolveSafeTarget(ctx, host)
	cancel()
	if err != nil {
		return err
	}
	ip := net.ParseIP(ips[0])
	if ip == nil {
		return errors.New("некорректный IP для UDP")
	}
	_, err = r.conn.WriteToUDP(data, &net.UDPAddr{IP: ip, Port: int(port)})
	return err
}

func (r *serverUDPRelay) Close() error {
	return r.conn.Close()
}

func (s *Server) openGuardedUDP(_ context.Context, _ uint32, reply func(atyp byte, host string, port uint16, data []byte) error) (udpHandler, error) {
	uc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	rel := &serverUDPRelay{server: s, conn: uc, reply: reply}
	go rel.readLoop()
	return rel, nil
}

func (s *Server) resolveSafeTarget(ctx context.Context, host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !isAllowedTargetIP(ip, s.cfg.AllowPrivateTargets) {
			return nil, fmt.Errorf("доступ к локальному адресу %s запрещён", ip.String())
		}
		return []string{ip.String()}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("не удалось разрешить %s", host)
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if isAllowedTargetIP(a.IP, s.cfg.AllowPrivateTargets) {
			out = append(out, a.IP.String())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("адрес %s разрешается в запрещённую локальную сеть", host)
	}
	return out, nil
}

func isAllowedTargetIP(ip net.IP, allowPrivate bool) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if !allowPrivate && (ip.IsLoopback() || ip.IsPrivate()) {
		return false
	}
	return true
}

type replayGuard struct {
	mu      sync.Mutex
	seen    map[string]int64
	lastGC  time.Time
}

func newReplayGuard() *replayGuard {
	return &replayGuard{
		seen:   make(map[string]int64),
		lastGC: time.Now(),
	}
}

func (g *replayGuard) TryConsume(id string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	nowUnix := now.Unix()
	ttl := int64(MaxClockSkew.Seconds()*2) + 15
	if now.Sub(g.lastGC) > 30*time.Second || len(g.seen) > 4096 {
		for k, ts := range g.seen {
			if nowUnix-ts > ttl {
				delete(g.seen, k)
			}
		}
		g.lastGC = now
	}
	if _, exists := g.seen[id]; exists {
		return false
	}
	if len(g.seen) >= 65536 {
		// Safety cap under sustained flood: drop oldest quarter via map sweep.
		dropped := 0
		for k := range g.seen {
			delete(g.seen, k)
			dropped++
			if dropped >= 16384 {
				break
			}
		}
	}
	g.seen[id] = nowUnix
	return true
}
