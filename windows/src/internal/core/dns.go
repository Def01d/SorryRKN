package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var AIHosts = []string{"chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "claude.ai", "anthropic.com", "claudeusercontent.com", "gemini.google.com", "bard.google.com", "aistudio.google.com", "generativelanguage.googleapis.com", "gemini-pa.googleapis.com", "proactivebackend-pa.googleapis.com", "alkalimakersuite-pa.googleapis.com", "alkalimakersuite-pa.clients6.google.com"}

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
	if !ok || len(dns) > 4096 {
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
	expires  time.Time
}
type SmartDNS struct {
	mu     sync.Mutex
	cache  map[string]cachedDNS
	client *http.Client
}

func NewSmartDNS() *SmartDNS {
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if strings.HasPrefix(address, "dns.comss.one:") {
			address = "195.133.25.16:443"
		}
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}}
	return &SmartDNS{cache: make(map[string]cachedDNS), client: &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("DNS redirect rejected") }}}
}
func (s *SmartDNS) Resolve(ctx context.Context, q []byte) []byte {
	host, typ, _, e := Question(q)
	if e != nil {
		return nil
	}
	if !IsAI(host) {
		return nil
	}
	if typ == 28 || typ == 64 || typ == 65 {
		return DNSReply(q, 0)
	}
	key := host + ":" + string(rune(typ))
	s.mu.Lock()
	cached, ok := s.cache[key]
	s.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		out := append([]byte(nil), cached.response...)
		copy(out[:2], q[:2])
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "POST", "https://dns.comss.one/dns-query", bytes.NewReader(q))
	if e != nil {
		return DNSReply(q, 2)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	r, e := s.client.Do(req)
	if e != nil {
		return DNSReply(q, 2)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return DNSReply(q, 2)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 4097))
	if e != nil || len(b) > 4096 || len(b) < 12 || b[2]&128 == 0 {
		return DNSReply(q, 2)
	}
	name, qt, _, e := Question(b)
	if e != nil || name != host || qt != typ {
		return DNSReply(q, 2)
	}
	copy(b[:2], q[:2])
	s.mu.Lock()
	if len(s.cache) > 512 {
		s.cache = make(map[string]cachedDNS)
	}
	s.cache[key] = cachedDNS{response: append([]byte(nil), b...), expires: time.Now().Add(30 * time.Second)}
	s.mu.Unlock()
	return b
}
