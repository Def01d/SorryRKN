package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var AIHosts = []string{
	"chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "oaistatsig.com", "openaimerge.com",
	"cdn.workos.com", "forwarder.workos.com", "images.workoscdn.com", "setup.workos.com", "workos.imgix.net",
	"claude.ai", "anthropic.com", "claudeusercontent.com", "gemini.google.com", "bard.google.com", "aistudio.google.com",
	"generativelanguage.googleapis.com", "gemini-pa.googleapis.com", "proactivebackend-pa.googleapis.com", "alkalimakersuite-pa.googleapis.com", "alkalimakersuite-pa.clients6.google.com",
}

// These domains need ordinary public answers, not the regional AI relay.
var ProtectedDNSHosts = []string{
	"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtubei.googleapis.com", "youtube.googleapis.com",
	"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com", "discordstatus.com",
	"instagram.com", "cdninstagram.com", "fbcdn.net",
	"telegram.org", "telegram.me", "t.me", "telegra.ph", "telesco.pe",
}

func IsAI(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range AIHosts {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
func Question(packet []byte) (string, uint16, int, error) {
	if len(packet) < 12 || binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return "", 0, 0, errors.New("invalid DNS question")
	}
	pos := 12
	var labels []string
	total := 0
	for {
		if pos >= len(packet) {
			return "", 0, 0, io.ErrUnexpectedEOF
		}
		n := int(packet[pos])
		pos++
		if n == 0 {
			break
		}
		if n > 63 || pos+n > len(packet) {
			return "", 0, 0, errors.New("invalid DNS name")
		}
		part := packet[pos : pos+n]
		for _, c := range part {
			if c < 33 || c > 126 {
				return "", 0, 0, errors.New("invalid DNS label")
			}
		}
		labels = append(labels, string(part))
		pos += n
		total += n + 1
		if total > 254 {
			return "", 0, 0, errors.New("DNS name too long")
		}
	}
	if pos+4 > len(packet) || binary.BigEndian.Uint16(packet[pos+2:pos+4]) != 1 {
		return "", 0, 0, errors.New("invalid DNS class")
	}
	return strings.ToLower(strings.Join(labels, ".")), binary.BigEndian.Uint16(packet[pos : pos+2]), pos + 4, nil
}
func DNSReply(query []byte, rcode uint16) []byte {
	_, _, end, e := Question(query)
	if e != nil {
		return nil
	}
	result := append([]byte(nil), query[:end]...)
	binary.BigEndian.PutUint16(result[2:4], 0x8080|(binary.BigEndian.Uint16(query[2:4])&0x0100)|(rcode&15))
	for i := 6; i < 12; i++ {
		result[i] = 0
	}
	return result
}
func DNSPayload(packet []byte) ([]byte, int, bool) {
	if len(packet) < 28 {
		return nil, 0, false
	}
	var offset int
	switch packet[0] >> 4 {
	case 4:
		offset = int(packet[0]&15) * 4
		if offset < 20 || len(packet) < offset+8 || packet[9] != 17 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return nil, 0, false
		}
	case 6:
		if len(packet) < 48 || packet[6] != 17 {
			return nil, 0, false
		}
		offset = 40
	default:
		return nil, 0, false
	}
	if binary.BigEndian.Uint16(packet[offset+2:offset+4]) != 53 {
		return nil, 0, false
	}
	length := int(binary.BigEndian.Uint16(packet[offset+4 : offset+6]))
	if length < 20 || offset+length > len(packet) {
		return nil, 0, false
	}
	return packet[offset+8 : offset+length], offset, true
}
func ReplyPacket(original, dns []byte) []byte {
	_, offset, ok := DNSPayload(original)
	if !ok || len(dns) < 12 || len(dns) > 4096 {
		return nil
	}
	out := make([]byte, offset+8+len(dns))
	copy(out, original[:offset+8])
	copy(out[offset+8:], dns)
	if original[0]>>4 == 4 {
		copy(out[12:16], original[16:20])
		copy(out[16:20], original[12:16])
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		out[8] = 64
		out[10] = 0
		out[11] = 0
	} else {
		copy(out[8:24], original[24:40])
		copy(out[24:40], original[8:24])
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
		out[7] = 64
	}
	copy(out[offset:offset+2], original[offset+2:offset+4])
	copy(out[offset+2:offset+4], original[offset:offset+2])
	binary.BigEndian.PutUint16(out[offset+4:offset+6], uint16(8+len(dns)))
	out[offset+6] = 0
	out[offset+7] = 0
	return out
}

type cachedDNS struct {
	response []byte
	stored   time.Time
	expires  time.Time
}
type SmartDNS struct {
	mu              sync.Mutex
	cache           map[string]cachedDNS
	client          *http.Client
	fallbacks       []*http.Client
	preferred       int
	public          []dnsUpstream
	publicPreferred int
	rules           DomainRules
	chatGPTRoute    chatGPTRoute
	chatGPTFlight   chan struct{}
	chatGPTProbe    func(context.Context, string) error
}

type dnsUpstream struct {
	url    string
	client *http.Client
}

func NewSmartDNS(rules ...DomainRules) *SmartDNS {
	selected := DomainRules{Builtin: true}
	if len(rules) > 0 {
		selected = rules[0]
	}
	// Keep normal hostname resolution so provider address changes are picked up.
	// Published bootstrap addresses recover when the local DNS or one route fails.
	// Each route keeps the original HTTPS hostname and certificate verification.
	// Source: https://www.comss.ru/page.php?id=7315
	s := &SmartDNS{rules: selected, cache: make(map[string]cachedDNS), client: newDNSClient("dns.comss.one", "")}
	for _, address := range []string{"212.109.195.93", "83.220.169.155", "195.133.25.16"} {
		s.fallbacks = append(s.fallbacks, newDNSClient("dns.comss.one", address))
	}
	// Wire-format DoH with bootstrap IPs does not depend on the ISP's resolver.
	for _, endpoint := range [][2]string{{"cloudflare-dns.com", "1.1.1.1"}, {"dns.google", "8.8.8.8"}, {"cloudflare-dns.com", "1.0.0.1"}, {"dns.google", "8.8.4.4"}} {
		s.public = append(s.public, dnsUpstream{url: "https://" + endpoint[0] + "/dns-query", client: newDNSClient(endpoint[0], endpoint[1])})
	}
	return s
}

func newDNSClient(host, bootstrap string) *http.Client {
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 2 * time.Second, IdleConnTimeout: 30 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if bootstrap != "" && address == host+":443" {
			address = net.JoinHostPort(bootstrap, "443")
		}
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, address)
	}}
	return &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("DNS redirect rejected") }}
}

func (s *SmartDNS) Close() {
	s.client.CloseIdleConnections()
	for _, client := range s.fallbacks {
		client.CloseIdleConnections()
	}
	for _, endpoint := range s.public {
		endpoint.client.CloseIdleConnections()
	}
}

// DialContext permits read-only diagnostics through the same DNS routes without
// loading WinDivert or changing the machine's DNS. The caller's TLS transport
// still uses the original hostname for SNI and certificate verification.
func (s *SmartDNS) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	host, port, err := net.SplitHostPort(address)
	if err != nil || !s.rules.ShouldResolveDNS(host) {
		return dialer.DialContext(ctx, network, address)
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, err
	}
	qt := dnsmessage.TypeA
	if strings.HasSuffix(network, "6") {
		qt = dnsmessage.TypeAAAA
	}
	message := dnsmessage.Message{Header: dnsmessage.Header{RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: qt, Class: dnsmessage.ClassINET}}}
	q, err := message.Pack()
	if err != nil {
		return nil, err
	}
	response := s.Resolve(ctx, q)
	if err = message.Unpack(response); err != nil {
		return nil, &net.DNSError{Name: host, Err: "invalid secure DNS response"}
	}
	if message.RCode != dnsmessage.RCodeSuccess {
		return nil, &net.DNSError{Name: host, Err: fmt.Sprintf("secure DNS response code %d", message.RCode), IsNotFound: message.RCode == dnsmessage.RCodeNameError}
	}
	var lastErr error
	for _, answer := range message.Answers {
		var ip net.IP
		switch record := answer.Body.(type) {
		case *dnsmessage.AResource:
			if qt == dnsmessage.TypeA {
				ip = net.IP(record.A[:])
			}
		case *dnsmessage.AAAAResource:
			if qt == dnsmessage.TypeAAAA {
				ip = net.IP(record.AAAA[:])
			}
		}
		if ip == nil {
			continue
		}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &net.DNSError{Name: host, Err: "secure DNS returned no address", IsNotFound: true}
}

func (s *SmartDNS) Resolve(ctx context.Context, q []byte) []byte {
	host, typ, _, e := Question(q)
	if e != nil || q[2]&0xf8 != 0 || len(q) > 4096 {
		return nil
	}
	if !s.rules.ShouldResolveDNS(host) {
		return nil
	}
	geo := s.rules.IsGeo(host)
	// The regional relay is IPv4-only. HTTPS/SVCB hints can enable ECH or QUIC
	// and bypass the visible TLS hostname used by the selected DPI profile.
	if geo && typ == 28 || typ == 64 || typ == 65 {
		return DNSReply(q, 0)
	}
	// Include flags, question case and EDNS options, not just the domain and type.
	// In particular, a DNSSEC or client-subnet query must not reuse another answer.
	key := string(q[2:])
	s.mu.Lock()
	cached, ok := s.cache[key]
	s.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		if out := cachedDNSReply(cached, q); out != nil {
			return s.preferChatGPT(ctx, host, typ, out)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	b := s.query(ctx, q, !geo)
	if b == nil {
		return DNSReply(q, 2)
	}
	if ttl := dnsCacheTTL(b); ttl > 0 {
		now := time.Now()
		s.mu.Lock()
		if len(s.cache) >= 512 {
			s.cache = make(map[string]cachedDNS)
		}
		s.cache[key] = cachedDNS{response: append([]byte(nil), b...), stored: now, expires: now.Add(ttl)}
		s.mu.Unlock()
	}
	return s.preferChatGPT(ctx, host, typ, b)
}

func (s *SmartDNS) query(ctx context.Context, q []byte, public bool) []byte {
	q = append([]byte(nil), q...)
	endpoints := []dnsUpstream{{url: "https://dns.comss.one/dns-query", client: s.client}}
	for _, client := range s.fallbacks {
		endpoints = append(endpoints, dnsUpstream{url: endpoints[0].url, client: client})
	}
	s.mu.Lock()
	preferred := s.preferred
	if public {
		endpoints = s.public
		preferred = s.publicPreferred
	}
	s.mu.Unlock()
	if len(endpoints) == 0 {
		return nil
	}
	preferred %= len(endpoints)
	type result struct {
		packet []byte
		route  int
	}
	results := make(chan result, len(endpoints))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for i := range endpoints {
		route := (preferred + i) % len(endpoints)
		go func(delay time.Duration, route int) {
			if delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					return
				}
			}
			results <- result{packet: queryDNS(ctx, endpoints[route], q), route: route}
		}(time.Duration(i)*200*time.Millisecond, route)
	}
	for range endpoints {
		select {
		case <-ctx.Done():
			return nil
		case r := <-results:
			if r.packet != nil {
				s.mu.Lock()
				if public {
					s.publicPreferred = r.route
				} else {
					s.preferred = r.route
				}
				s.mu.Unlock()
				return r.packet
			}
		}
	}
	return nil
}

func queryDNS(ctx context.Context, endpoint dnsUpstream, q []byte) []byte {
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint.url, bytes.NewReader(q))
	if e != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	r, e := endpoint.client.Do(req)
	if e != nil {
		return nil
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 4097))
	if e != nil || len(b) > 4096 || len(b) < 12 || b[2]&128 == 0 || b[2]&2 != 0 || b[2]&0x78 != q[2]&0x78 {
		return nil
	}
	host, typ, _, _ := Question(q)
	name, qt, _, e := Question(b)
	if e != nil || name != host || qt != typ {
		return nil
	}
	var message dnsmessage.Message
	if message.Unpack(b) != nil || message.RCode != dnsmessage.RCodeSuccess && message.RCode != dnsmessage.RCodeNameError {
		return nil
	}
	copy(b[:2], q[:2])
	return b
}

func dnsCacheTTL(packet []byte) time.Duration {
	var message dnsmessage.Message
	if message.Unpack(packet) != nil || message.Truncated || message.RCode != dnsmessage.RCodeSuccess && message.RCode != dnsmessage.RCodeNameError {
		return 0
	}
	ttl := uint32(30)
	if len(message.Answers) == 0 || message.RCode == dnsmessage.RCodeNameError {
		// RFC 2308: negative answers need an SOA to define their lifetime.
		found := false
		for _, rr := range message.Authorities {
			if soa, ok := rr.Body.(*dnsmessage.SOAResource); ok {
				ttl = min(ttl, rr.Header.TTL, soa.MinTTL)
				found = true
			}
		}
		if !found {
			return 0
		}
	}
	for _, section := range [][]dnsmessage.Resource{message.Answers, message.Authorities, message.Additionals} {
		for _, rr := range section {
			if rr.Header.Type != dnsmessage.TypeOPT {
				ttl = min(ttl, rr.Header.TTL)
			}
		}
	}
	return time.Duration(ttl) * time.Second
}

func cachedDNSReply(cached cachedDNS, query []byte) []byte {
	var message dnsmessage.Message
	if message.Unpack(cached.response) != nil {
		return nil
	}
	message.ID = binary.BigEndian.Uint16(query[:2])
	age := uint32(max(0, time.Since(cached.stored)/time.Second))
	for _, section := range [][]dnsmessage.Resource{message.Answers, message.Authorities, message.Additionals} {
		for i := range section {
			if section[i].Header.Type != dnsmessage.TypeOPT {
				section[i].Header.TTL -= min(age, section[i].Header.TTL)
			}
		}
	}
	packet, err := message.Pack()
	if err != nil || len(packet) > 4096 {
		return nil
	}
	return packet
}
