package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsAnswer(q []byte, ttl uint32) []byte {
	r := DNSReply(q, 0)
	binary.BigEndian.PutUint16(r[6:8], 1)
	r = append(r, 0xc0, 12, 0, 1, 0, 1, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl), 0, 4, 192, 0, 2, 1)
	return r
}

func testDNSClient(reply func([]byte) []byte) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		q, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(reply(q))), Header: make(http.Header)}, nil
	})}
}

func TestDNSFallbackRecoversFromUnreachableOrBrokenPrimary(t *testing.T) {
	for _, mode := range []string{"timeout", "servfail", "malformed", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			var primary, fallback atomic.Int32
			s := NewSmartDNS()
			defer s.Close()
			s.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				primary.Add(1)
				if mode == "timeout" {
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				q, _ := io.ReadAll(r.Body)
				response := DNSReply(q, 2)
				if mode == "malformed" {
					response = dnsAnswer(q, 30)
					response = response[:len(response)-1]
				}
				if mode == "truncated" {
					response = dnsAnswer(q, 30)
					response[2] |= 2
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(response)), Header: make(http.Header)}, nil
			})}
			s.fallbacks = []*http.Client{testDNSClient(func(q []byte) []byte { fallback.Add(1); return dnsAnswer(q, 30) })}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r := s.Resolve(ctx, query("chatgpt.com", 1))
			if len(r) < 12 || r[3]&15 != 0 || binary.BigEndian.Uint16(r[6:8]) != 1 {
				t.Fatalf("fallback failed: %x", r)
			}
			// A different name misses the cache and must prefer the working route.
			s.Resolve(ctx, query("api.openai.com", 1))
			if primary.Load() != 1 || fallback.Load() != 2 {
				t.Fatalf("healthy route not retained: primary=%d fallback=%d", primary.Load(), fallback.Load())
			}
		})
	}
}

func TestDNSFailureIsNotCached(t *testing.T) {
	s := NewSmartDNS()
	defer s.Close()
	s.fallbacks = nil
	var requests int
	s.client = testDNSClient(func(q []byte) []byte {
		requests++
		if requests == 1 {
			return DNSReply(q, 2)
		}
		return dnsAnswer(q, 30)
	})
	q := query("chatgpt.com", 1)
	if r := s.Resolve(context.Background(), q); r[3]&15 != 2 {
		t.Fatal("expected initial failure")
	}
	if r := s.Resolve(context.Background(), q); r[3]&15 != 0 || requests != 2 {
		t.Fatal("temporary failure was cached")
	}
}

func TestDNSCacheRespectsTTLFlagsAndAging(t *testing.T) {
	s := NewSmartDNS()
	defer s.Close()
	s.fallbacks = nil
	var requests int
	s.client = testDNSClient(func(q []byte) []byte { requests++; return dnsAnswer(q, 5) })
	q := query("chatgpt.com", 1)
	s.Resolve(context.Background(), q)
	key := string(q[2:])
	cached := s.cache[key]
	if cached.expires.Sub(cached.stored) != 5*time.Second {
		t.Fatal("answer lifetime ignored")
	}
	cached.stored = cached.stored.Add(-3 * time.Second)
	s.cache[key] = cached
	q[0] = 9
	r := s.Resolve(context.Background(), q)
	var message dnsmessage.Message
	if message.Unpack(r) != nil || message.ID != binary.BigEndian.Uint16(q[:2]) || message.Answers[0].Header.TTL != 2 || requests != 1 {
		t.Fatal("cached answer did not age or restore transaction ID", message, requests)
	}
	q[3] |= 0x10 // Checking Disabled must be a different cache entry.
	s.Resolve(context.Background(), q)
	if requests != 2 {
		t.Fatal("different query flags reused cache")
	}
	if dnsCacheTTL(dnsAnswer(q, 0)) != 0 || dnsCacheTTL(DNSReply(q, 0)) != 0 {
		t.Fatal("zero TTL or SOA-less NODATA cached")
	}
}

func TestDNSPublicAndRegionalRoutesAreSeparate(t *testing.T) {
	s := NewSmartDNS(DomainRules{Builtin: true, Secure: true, Direct: []string{"private.youtube.com"}})
	defer s.Close()
	s.fallbacks = nil
	var geoCalls, publicCalls int
	s.client = testDNSClient(func(q []byte) []byte { geoCalls++; return dnsAnswer(q, 30) })
	s.public = []dnsUpstream{{url: "https://resolver.example/dns-query", client: testDNSClient(func(q []byte) []byte { publicCalls++; return dnsAnswer(q, 30) })}}
	for _, host := range []string{"chatgpt.com", "cdn.workos.com", "oaistatsig.com"} {
		s.Resolve(context.Background(), query(host, 1))
	}
	for _, host := range []string{"www.youtube.com", "r1.googlevideo.com", "gateway.discord.gg", "cdn.discordapp.com", "instagram.com", "static.cdninstagram.com", "web.telegram.org"} {
		s.Resolve(context.Background(), query(host, 1))
	}
	for _, host := range []string{"private.youtube.com", "youtube.com.evil.example", "google.com", "unrelated.example"} {
		if s.Resolve(context.Background(), query(host, 1)) != nil {
			t.Fatal("unrelated or direct query intercepted", host)
		}
	}
	if geoCalls != 3 || publicCalls != 7 {
		t.Fatal("DNS provider classes mixed", geoCalls, publicCalls)
	}
	// An unavailable relay must not silently switch ChatGPT to direct public IPs.
	s.client = testDNSClient(func(q []byte) []byte { return DNSReply(q, 2) })
	if r := s.Resolve(context.Background(), query("api.openai.com", 1)); r[3]&15 != 2 || publicCalls != 7 {
		t.Fatal("regional lookup escaped to public resolver")
	}
}

func TestDNSCancellationAndEmptyReply(t *testing.T) {
	s := NewSmartDNS()
	defer s.Close()
	s.fallbacks = nil
	s.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if r := s.Resolve(ctx, query("chatgpt.com", 1)); len(r) < 12 || r[3]&15 != 2 || time.Since(start) > time.Second {
		t.Fatal("cancellation did not return SERVFAIL promptly")
	}
	if ReplyPacket(make([]byte, 28), nil) != nil {
		t.Fatal("empty reply accepted")
	}
}

func TestDNSPublicIPv6AndHTTPSHints(t *testing.T) {
	s := NewSmartDNS(DomainRules{Secure: true})
	defer s.Close()
	var calls int
	s.public = []dnsUpstream{{url: "https://resolver.example/dns-query", client: testDNSClient(func(q []byte) []byte { calls++; return DNSReply(q, 0) })}}
	s.Resolve(context.Background(), query("youtube.com", 28))
	for _, qt := range []uint16{64, 65} {
		if r := s.Resolve(context.Background(), query("youtube.com", qt)); len(r) < 12 || r[3]&15 != 0 {
			t.Fatal("HTTPS hints were not suppressed")
		}
	}
	if calls != 1 {
		t.Fatal("public IPv6 should resolve, HTTPS hints should not", calls)
	}
}

func TestDNSLiveProviders(t *testing.T) {
	if os.Getenv("SORRYRKN_TEST_LIVE_DNS") != "1" {
		t.Skip("set SORRYRKN_TEST_LIVE_DNS=1 for read-only provider connectivity test")
	}
	s := NewSmartDNS(DomainRules{Builtin: true, Secure: true})
	defer s.Close()
	for _, host := range []string{"chatgpt.com", "www.youtube.com", "gateway.discord.gg", "www.instagram.com", "web.telegram.org"} {
		t.Run(host, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			packet := s.Resolve(ctx, query(host, 1))
			var message dnsmessage.Message
			if err := message.Unpack(packet); err != nil {
				t.Fatal(err)
			}
			if message.RCode != dnsmessage.RCodeSuccess || len(message.Answers) == 0 {
				t.Fatal("provider did not return addresses", message.RCode)
			}
			for _, answer := range message.Answers {
				if address, ok := answer.Body.(*dnsmessage.AResource); ok {
					t.Logf("%s -> %v", host, address.A)
				}
			}
		})
	}
}

func TestDNSDialHonorsDirectExclusion(t *testing.T) {
	s := NewSmartDNS(DomainRules{Builtin: true, Direct: []string{"chatgpt.com"}})
	defer s.Close()
	var calls atomic.Int32
	s.client = testDNSClient(func(q []byte) []byte { calls.Add(1); return dnsAnswer(q, 30) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.DialContext(ctx, "tcp", "chatgpt.com:443")
	if err == nil || !errors.Is(err, context.Canceled) || calls.Load() != 0 {
		t.Fatal("direct exclusion did not use system dial", err, calls.Load())
	}
}

func TestDNSDialUsesResolvedAddress(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s := NewSmartDNS(DomainRules{Geo: []string{"no-system-dns.invalid"}})
	defer s.Close()
	s.fallbacks = nil
	s.client = testDNSClient(func(q []byte) []byte {
		response := dnsAnswer(q, 30)
		copy(response[len(response)-4:], []byte{127, 0, 0, 1})
		return response
	})
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := s.DialContext(ctx, "tcp", net.JoinHostPort("no-system-dns.invalid", port))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

func TestDNSNegativeCacheUsesSOAMinimum(t *testing.T) {
	name := dnsmessage.MustNewName("chatgpt.com.")
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeNameError},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Authorities: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 120},
			Body:   &dnsmessage.SOAResource{NS: name, MBox: name, MinTTL: 4},
		}},
	}
	packet, err := message.Pack()
	if err != nil || dnsCacheTTL(packet) != 4*time.Second {
		t.Fatal("negative TTL did not honor SOA", err)
	}
	message.Authorities = nil
	packet, _ = message.Pack()
	if dnsCacheTTL(packet) != 0 {
		t.Fatal("SOA-less NXDOMAIN should not be cached")
	}
}
