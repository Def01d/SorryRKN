package mirage

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

type managedCarrier struct {
	mux       *muxCarrier
	byteLimit int64
	ageLimit  time.Duration
}

// Client terminates local SOCKS5 connections and tunnels them over rotated,
// covertly authenticated SRKN-Mirage carriers.
type Client struct {
	cfg *ClientConfig

	ctx    context.Context
	cancel context.CancelFunc

	lnMu sync.Mutex
	ln   net.Listener

	poolMu   sync.Mutex
	active   *managedCarrier
	retiring []*managedCarrier
	dialing  chan struct{}

	wg sync.WaitGroup
}

// NewClient constructs a Client for cfg.
func NewClient(cfg *ClientConfig) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("не задана конфигурация mirage")
	}
	if cfg.ServerHost == "" || cfg.ServerPort == 0 {
		return nil, errors.New("не задан адрес сервера mirage")
	}
	copyCfg := *cfg
	if copyCfg.ListenAddr == "" {
		copyCfg.ListenAddr = "127.0.0.1:0"
	}
	if copyCfg.CoverHost == "" {
		if copyCfg.SNI != "" {
			copyCfg.CoverHost = copyCfg.SNI
		} else {
			copyCfg.CoverHost = copyCfg.ServerHost
		}
	}
	if copyCfg.Fingerprint == "" {
		copyCfg.Fingerprint = "chrome"
	}
	if copyCfg.MTU <= 0 {
		copyCfg.MTU = DefaultMTU
	}
	if len(copyCfg.DoHURLs) == 0 {
		copyCfg.DoHURLs = []string{
			"https://1.1.1.1/dns-query",
			"https://dns.google/resolve",
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		cfg:    &copyCfg,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start binds the SOCKS5 listener and serves asynchronously until Close or ctx cancel.
func (c *Client) Start(ctx context.Context) (string, error) {
	ln, err := net.Listen("tcp", c.cfg.ListenAddr)
	if err != nil {
		return "", fmt.Errorf("не удалось открыть локальный порт mirage: %w", err)
	}
	c.lnMu.Lock()
	c.ln = ln
	c.lnMu.Unlock()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-c.ctx.Done():
		}
	}()

	c.wg.Add(1)
	go c.acceptLoop(ln)
	return ln.Addr().String(), nil
}

// Serve runs the SOCKS5 server synchronously until ctx is canceled.
func (c *Client) Serve(ctx context.Context) error {
	if _, err := c.Start(ctx); err != nil {
		return err
	}
	c.wg.Wait()
	return nil
}

// Close shuts down the listener and all active/retiring carriers.
func (c *Client) Close() error {
	c.cancel()
	c.lnMu.Lock()
	ln := c.ln
	c.ln = nil
	c.lnMu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}

	c.poolMu.Lock()
	active := c.active
	c.active = nil
	retiring := c.retiring
	c.retiring = nil
	c.poolMu.Unlock()

	if active != nil {
		_ = active.mux.Close()
	}
	for _, r := range retiring {
		_ = r.mux.Close()
	}
	c.wg.Wait()
	return nil
}

func (c *Client) acceptLoop(ln net.Listener) {
	defer c.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		c.wg.Add(1)
		go func(nc net.Conn) {
			defer c.wg.Done()
			c.handleSOCKS5(nc)
		}(conn)
	}
}

func (c *Client) acquireCarrier(ctx context.Context) (*muxCarrier, error) {
	for {
		c.poolMu.Lock()
		if c.ctx.Err() != nil {
			c.poolMu.Unlock()
			return nil, errors.New("клиент mirage остановлен")
		}
		c.reapRetiredLocked()
		if c.active != nil {
			select {
			case <-c.active.mux.Done():
				c.active = nil
			default:
				if c.active.mux.BytesMoved() < c.active.byteLimit &&
					time.Since(c.active.mux.createdAt) < c.active.ageLimit {
					m := c.active.mux
					c.poolMu.Unlock()
					return m, nil
				}
				c.active.mux.MarkRetired()
				c.retiring = append(c.retiring, c.active)
				c.active = nil
			}
		}
		if c.dialing != nil {
			waitCh := c.dialing
			c.poolMu.Unlock()
			select {
			case <-waitCh:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-c.ctx.Done():
				return nil, errors.New("клиент mirage остановлен")
			}
		}
		waitCh := make(chan struct{})
		c.dialing = waitCh
		c.poolMu.Unlock()

		mc, err := c.dialManagedCarrier(ctx)

		c.poolMu.Lock()
		if err == nil {
			if c.active != nil {
				c.active.mux.MarkRetired()
				c.retiring = append(c.retiring, c.active)
			}
			c.active = mc
		}
		c.dialing = nil
		close(waitCh)
		c.poolMu.Unlock()

		if err != nil {
			return nil, err
		}
		return mc.mux, nil
	}
}

func (c *Client) reapRetiredLocked() {
	kept := c.retiring[:0]
	for _, r := range c.retiring {
		select {
		case <-r.mux.Done():
			continue
		default:
			if r.mux.ActiveCount() == 0 {
				_ = r.mux.Close()
				continue
			}
			kept = append(kept, r)
		}
	}
	c.retiring = kept
}

func (c *Client) scheduleReap() {
	c.poolMu.Lock()
	c.reapRetiredLocked()
	c.poolMu.Unlock()
}

func (c *Client) dialManagedCarrier(ctx context.Context) (*managedCarrier, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	ips, err := c.resolveEndpoints(dialCtx)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, strconv.Itoa(int(c.cfg.ServerPort)))
		mc, derr := c.dialEndpoint(dialCtx, addr)
		if derr == nil {
			return mc, nil
		}
		lastErr = derr
	}
	if lastErr == nil {
		lastErr = errors.New("не удалось подключиться к серверу mirage")
	}
	return nil, lastErr
}

func (c *Client) resolveEndpoints(ctx context.Context) ([]string, error) {
	host := c.cfg.ServerHost
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, nil
	}
	if addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host); err == nil && len(addrs) > 0 {
		out := make([]string, 0, len(addrs))
		for _, a := range addrs {
			if !a.IP.IsUnspecified() && !a.IP.IsMulticast() {
				out = append(out, a.IP.String())
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	// DoH fallback when ISP DNS is blocked or poisoned.
	for _, dohBase := range c.cfg.DoHURLs {
		ips, err := lookupDoH(ctx, dohBase, host)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
	}
	return nil, fmt.Errorf("не удалось разрешить адрес %s ни через системный DNS, ни через DoH", host)
}

func lookupDoH(ctx context.Context, base, host string) ([]string, error) {
	reqURL := base + "?name=" + url.QueryEscape(host) + "&type=A"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	hc := &http.Client{Timeout: 4 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	var parsed struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32*1024)).Decode(&parsed); err != nil {
		return nil, err
	}
	var out []string
	for _, ans := range parsed.Answer {
		if ans.Type == 1 || ans.Type == 28 {
			if ip := net.ParseIP(strings.TrimSpace(ans.Data)); ip != nil {
				out = append(out, ip.String())
			}
		}
	}
	return out, nil
}

func selectHelloID(fp string) utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(fp)) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "ios":
		return utls.HelloIOS_Auto
	case "random", "randomized":
		return utls.HelloRandomizedALPN
	default:
		return utls.HelloChrome_Auto
	}
}

func (c *Client) dialEndpoint(ctx context.Context, addr string) (*managedCarrier, error) {
	var d net.Dialer
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := rawConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	expectedPin := c.cfg.PinSHA256
	tlsCfg := &utls.Config{
		ServerName:         c.cfg.SNI,
		InsecureSkipVerify: true, // Pin-verified in VerifyPeerCertificate below.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("сервер не предъявил TLS-сертификат")
			}
			sum := sha256.Sum256(rawCerts[0])
			if !hmac.Equal(sum[:], expectedPin[:]) {
				return errors.New("отпечаток TLS-сертификата не совпадает с pin (возможен MITM)")
			}
			return nil
		},
	}

	uConn := utls.UClient(rawConn, tlsCfg, selectHelloID(c.cfg.Fingerprint))
	if err := uConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("TLS handshake mirage: %w", err)
	}

	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		_ = uConn.Close()
		return nil, err
	}
	var ephPub [32]byte
	copy(ephPub[:], ephPriv.PublicKey().Bytes())

	knockTok, cliNonce, err := buildKnockToken(c.cfg.Secret, ephPub, time.Now())
	if err != nil {
		_ = uConn.Close()
		return nil, err
	}

	if err := c.sendCovertHTTPKnock(ctx, uConn, knockTok); err != nil {
		_ = uConn.Close()
		return nil, err
	}

	br := bufio.NewReaderSize(uConn, 4096)
	dummyReq, _ := http.NewRequest(http.MethodPost, "https://"+c.cfg.CoverHost+"/api/v1/telemetry/events", nil)
	resp, err := http.ReadResponse(br, dummyReq)
	if err != nil {
		_ = uConn.Close()
		return nil, fmt.Errorf("некорректный HTTP-ответ носителя: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = uConn.Close()
		return nil, fmt.Errorf("сервер отклонил соединение (HTTP %d)", resp.StatusCode)
	}
	ackTok := resp.Header.Get("X-Session-Token")
	if ackTok == "" {
		_ = resp.Body.Close()
		_ = uConn.Close()
		return nil, errors.New("сервер ответил страницей прикрытия без токена сессии (проверьте ключ/время)")
	}

	srvPub, srvNonce, ok := verifyServerAck(c.cfg.Secret, ackTok, ephPub, cliNonce)
	if !ok {
		_ = uConn.Close()
		return nil, errors.New("подпись подтверждения сервера mirage недействительна")
	}
	peerPub, err := ecdh.X25519().NewPublicKey(srvPub[:])
	if err != nil {
		_ = uConn.Close()
		return nil, err
	}
	shared, err := ephPriv.ECDH(peerPub)
	if err != nil {
		_ = uConn.Close()
		return nil, err
	}
	keys := deriveSessionKeys(shared, c.cfg.Secret, cliNonce, srvNonce)

	bc := &bufferedConn{Conn: uConn, br: br}
	codec, err := newWireCodec(bc, true, keys, c.cfg.Chaff)
	if err != nil {
		_ = uConn.Close()
		return nil, err
	}

	byteLim := int64(randIntRange(6, 14)) * 1024 * 1024
	ageLim := time.Duration(randIntRange(180, 360)) * time.Second
	mux := newMuxCarrier(c.ctx, codec, true, carrierHooks{}, c.cfg.Chaff, c.scheduleReap)

	return &managedCarrier{
		mux:       mux,
		byteLimit: byteLim,
		ageLimit:  ageLim,
	}, nil
}

func (c *Client) sendCovertHTTPKnock(ctx context.Context, conn net.Conn, knockTok string) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
		defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	}
	padBytes := make([]byte, randIntRange(90, 240))
	_, _ = rand.Read(padBytes)
	nonceBytes := make([]byte, 8)
	_, _ = rand.Read(nonceBytes)

	body := fmt.Sprintf(`{"v":1,"ts":%d,"event":"heartbeat","nonce":"%s","metrics":"%s"}`,
		time.Now().Unix(),
		hex.EncodeToString(nonceBytes),
		hex.EncodeToString(padBytes),
	)

	req := fmt.Sprintf(
		"POST /api/v1/telemetry/events HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"+
			"Accept: application/json, text/plain, */*\r\n"+
			"Content-Type: application/json\r\n"+
			"Cookie: _sid=%s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: keep-alive\r\n\r\n%s",
		c.cfg.CoverHost,
		knockTok,
		len(body),
		body,
	)
	_, err := io.WriteString(conn, req)
	return err
}

func (c *Client) handleSOCKS5(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil || hdr[0] != 0x05 {
		return
	}
	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	requireAuth := c.cfg.AuthUser != "" || c.cfg.AuthPass != ""
	var chosen byte = 0xFF
	for _, m := range methods {
		if requireAuth && m == 0x02 {
			chosen = 0x02
			break
		}
		if !requireAuth && m == 0x00 {
			chosen = 0x00
			break
		}
	}
	if _, err := conn.Write([]byte{0x05, chosen}); err != nil || chosen == 0xFF {
		return
	}

	if chosen == 0x02 {
		if !c.authenticateSOCKS5UserPass(conn) {
			return
		}
	}

	var reqHdr [4]byte
	if _, err := io.ReadFull(conn, reqHdr[:]); err != nil || reqHdr[0] != 0x05 {
		return
	}
	cmd := reqHdr[1]
	atyp := reqHdr[3]
	host, port, err := readSOCKSAddr(conn, atyp)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_ = conn.SetDeadline(time.Time{})

	switch cmd {
	case 0x01: // CONNECT
		dialCtx, cancel := context.WithTimeout(c.ctx, 15*time.Second)
		carrier, err := c.acquireCarrier(dialCtx)
		if err != nil {
			cancel()
			_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		stream, err := carrier.DialStream(dialCtx, atyp, host, port)
		cancel()
		if err != nil {
			_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			_ = stream.Close()
			return
		}
		relayDuplex(conn, stream)

	case 0x03: // UDP ASSOCIATE
		carrier, err := c.acquireCarrier(c.ctx)
		if err != nil {
			_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		c.handleSOCKS5UDP(conn, carrier)

	default:
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

func (c *Client) authenticateSOCKS5UserPass(conn net.Conn) bool {
	var verLen [2]byte
	if _, err := io.ReadFull(conn, verLen[:]); err != nil || verLen[0] != 0x01 {
		return false
	}
	user := make([]byte, int(verLen[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return false
	}
	var pLen [1]byte
	if _, err := io.ReadFull(conn, pLen[:]); err != nil {
		return false
	}
	pass := make([]byte, int(pLen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return false
	}
	okUser := subtle.ConstantTimeCompare(user, []byte(c.cfg.AuthUser)) == 1
	okPass := subtle.ConstantTimeCompare(pass, []byte(c.cfg.AuthPass)) == 1
	if !okUser || !okPass {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return false
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err == nil
}

func (c *Client) handleSOCKS5UDP(ctrl net.Conn, carrier *muxCarrier) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_, _ = ctrl.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer func() { _ = udpConn.Close() }()

	uAddr := udpConn.LocalAddr().(*net.UDPAddr)
	reply := make([]byte, 10)
	reply[0], reply[1], reply[2], reply[3] = 0x05, 0x00, 0x00, 0x01
	copy(reply[4:8], net.IPv4(127, 0, 0, 1).To4())
	binary.BigEndian.PutUint16(reply[8:10], uint16(uAddr.Port))
	if _, err := ctrl.Write(reply); err != nil {
		return
	}

	var peerMu sync.Mutex
	var clientPeer *net.UDPAddr

	_, sendUDP, closeUDP := carrier.OpenClientUDP(func(atyp byte, host string, port uint16, data []byte) {
		peerMu.Lock()
		dst := clientPeer
		peerMu.Unlock()
		if dst == nil {
			return
		}
		addrBytes, err := encodeTargetAddr(atyp, host, port)
		if err != nil {
			return
		}
		pkt := make([]byte, 3+len(addrBytes)+len(data))
		// RSV(2)=0x0000, FRAG(1)=0x00
		copy(pkt[3:], addrBytes)
		copy(pkt[3+len(addrBytes):], data)
		_, _ = udpConn.WriteToUDP(pkt, dst)
	})
	defer closeUDP()

	// Monitor TCP control connection closure (RFC 1928).
	go func() {
		var discard [64]byte
		for {
			if _, err := ctrl.Read(discard[:]); err != nil {
				_ = udpConn.Close()
				return
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, src, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 10 || buf[2] != 0x00 {
			continue // Fragmented UDP unsupported by RFC 1928 simple relay.
		}
		atyp, host, port, used, err := decodeTargetAddr(buf[3:n])
		if err != nil {
			continue
		}
		peerMu.Lock()
		clientPeer = src
		peerMu.Unlock()

		payload := make([]byte, n-(3+used))
		copy(payload, buf[3+used:n])
		if err := sendUDP(atyp, host, port, payload); err != nil {
			return
		}
	}
}

func readSOCKSAddr(r io.Reader, atyp byte) (host string, port uint16, err error) {
	switch atyp {
	case AddrIPv4:
		var b [6]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[0:4]).String(), binary.BigEndian.Uint16(b[4:6]), nil
	case AddrIPv6:
		var b [18]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[0:16]).String(), binary.BigEndian.Uint16(b[16:18]), nil
	case AddrDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil || l[0] == 0 {
			return "", 0, errors.New("некорректная длина домена SOCKS5")
		}
		b := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		return string(b[:l[0]]), binary.BigEndian.Uint16(b[l[0]:]), nil
	default:
		return "", 0, errors.New("неподдерживаемый тип адреса SOCKS5")
	}
}

func relayDuplex(local net.Conn, stream *muxStream) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, local)
		_ = stream.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, stream)
		if tc, ok := local.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
	_ = stream.Close()
}

type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.br.Read(p)
}
