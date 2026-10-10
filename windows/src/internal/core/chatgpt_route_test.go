package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func routeAnswer(q []byte) []byte {
	var message dnsmessage.Message
	message.Unpack(q)
	message.Response = true
	message.AuthenticData = true
	for _, address := range [][4]byte{{132, 243, 112, 220}, {132, 243, 112, 221}} {
		message.Answers = append(message.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300}, Body: &dnsmessage.AResource{A: address}})
	}
	packet, _ := message.Pack()
	return packet
}

func TestChatGPTRoutePinsActualDNSAnswersAndExpires(t *testing.T) {
	s := NewSmartDNS(DomainRules{Builtin: true, Secure: true})
	defer s.Close()
	s.client = testDNSClient(routeAnswer)
	s.fallbacks = nil
	var probes atomic.Int32
	s.chatGPTProbe = func(ctx context.Context, address string) error {
		probes.Add(1)
		if address == "132.243.112.221" {
			return nil
		}
		return errors.New("HTTP 403 challenge")
	}
	check := func() {
		var response dnsmessage.Message
		if response.Unpack(s.Resolve(context.Background(), query("chatgpt.com", 1))) != nil || len(response.Answers) != 1 {
			t.Fatal("unverified addresses remained", response)
		}
		if response.AuthenticData || response.Answers[0].Header.TTL > 30 || net.IP(response.Answers[0].Body.(*dnsmessage.AResource).A[:]).String() != "132.243.112.221" {
			t.Fatal("wrong preferred answer", response)
		}
	}
	check()
	count := probes.Load()
	check()
	if probes.Load() != count || s.preferredChatGPT() != "132.243.112.221" {
		t.Fatal("preference not cached")
	}
	s.mu.Lock()
	s.chatGPTRoute.expires = time.Now().Add(-time.Second)
	s.mu.Unlock()
	check()
	if probes.Load() <= count {
		t.Fatal("expired route not checked again")
	}
	direct := NewSmartDNS(DomainRules{Builtin: true, Direct: []string{"chatgpt.com"}})
	defer direct.Close()
	direct.chatGPTProbe = func(context.Context, string) error { t.Error("direct exception probed"); return nil }
	if direct.Resolve(context.Background(), query("chatgpt.com", 1)) != nil {
		t.Fatal("direct exception intercepted")
	}
}

func TestChatGPTRouteCancellationCoalescesWithoutBlockingOtherDNS(t *testing.T) {
	s := NewSmartDNS(DomainRules{Builtin: true, Secure: true})
	defer s.Close()
	s.client = testDNSClient(routeAnswer)
	s.fallbacks = nil
	s.public = []dnsUpstream{{url: "https://test/dns-query", client: testDNSClient(func(q []byte) []byte { return dnsAnswer(q, 30) })}}
	entered := make(chan struct{}, 4)
	var exited atomic.Int32
	s.chatGPTProbe = func(ctx context.Context, address string) error {
		entered <- struct{}{}
		<-ctx.Done()
		exited.Add(1)
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	var done sync.WaitGroup
	done.Add(2)
	for range 2 {
		go func() { defer done.Done(); s.Resolve(ctx, query("chatgpt.com", 1)) }()
	}
	<-entered
	<-entered
	if out := s.Resolve(context.Background(), query("youtube.com", 1)); len(out) == 0 {
		t.Fatal("unrelated DNS blocked")
	}
	cancel()
	done.Wait()
	if exited.Load() != 2 || len(entered) != 0 {
		t.Fatal("duplicate or leaked probes", exited.Load(), len(entered))
	}
	if s.preferredChatGPT() != "" {
		t.Fatal("cancelled route cached")
	}
}

func TestChatGPTRouteRejectsIntermittentChallengeBeforePinning(t *testing.T) {
	s := NewSmartDNS(DomainRules{Builtin: true, Secure: true})
	defer s.Close()
	rejected := make(chan struct{})
	var unstable, stable atomic.Int32
	s.chatGPTProbe = func(ctx context.Context, address string) error {
		if address == "unstable" {
			if unstable.Add(1) == 1 {
				return nil
			}
			close(rejected)
			return errors.New("browser verification required")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rejected:
		}
		stable.Add(1)
		return nil
	}
	if selected := s.selectChatGPTRoute(context.Background(), []string{"unstable", "stable"}); selected != "stable" {
		t.Fatal("intermittent route selected", selected)
	}
	if unstable.Load() != 2 || stable.Load() != 2 {
		t.Fatal("route was not independently confirmed", unstable.Load(), stable.Load())
	}
}

func TestChatGPTRouteUnverifiedAnswersHaveShortClientTTL(t *testing.T) {
	for _, single := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed candidates", true: "one candidate"}[single], func(t *testing.T) {
			s := NewSmartDNS(DomainRules{Builtin: true, Secure: true})
			defer s.Close()
			s.fallbacks = nil
			s.client = testDNSClient(func(q []byte) []byte {
				var message dnsmessage.Message
				message.Unpack(routeAnswer(q))
				if single {
					message.Answers = message.Answers[:1]
				}
				message.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232, TTL: 0x8000}, Body: &dnsmessage.OPTResource{}}}
				packet, _ := message.Pack()
				return packet
			})
			var calls atomic.Int32
			s.chatGPTProbe = func(context.Context, string) error { calls.Add(1); return errors.New("challenge") }
			for range 2 {
				var reply dnsmessage.Message
				if err := reply.Unpack(s.Resolve(context.Background(), query("chatgpt.com", 1))); err != nil {
					t.Fatal(err)
				}
				want := 2
				if single {
					want = 1
				}
				if len(reply.Answers) != want {
					t.Fatal("fallback discarded addresses", reply)
				}
				for _, rr := range reply.Answers {
					if rr.Header.TTL > 15 {
						t.Fatal("unverified answer outlives negative cache", rr.Header.TTL)
					}
				}
				if reply.Additionals[0].Header.TTL != 0x8000 {
					t.Fatal("EDNS flags changed")
				}
			}
			if !single && calls.Load() != 2 {
				t.Fatal("failed selection was not cached", calls.Load())
			}
		})
	}
}

type sharedResolverExtra struct {
	fakeExtra
	resolver *SmartDNS
}

func (extra sharedResolverExtra) Resolver() *SmartDNS { return extra.resolver }

func TestEngineServiceHealthUsesInterceptedDNSRoute(t *testing.T) {
	resolver := NewSmartDNS(DomainRules{Builtin: true, Secure: true})
	defer resolver.Close()
	resolver.client = testDNSClient(routeAnswer)
	resolver.fallbacks = nil
	resolver.chatGPTProbe = func(_ context.Context, address string) error {
		if address == "132.243.112.221" {
			return nil
		}
		return errors.New("challenge")
	}
	// First resolve an application query, as the active packet interceptor does.
	applicationReply := resolver.Resolve(context.Background(), query("chatgpt.com", 1))
	resolver.chatGPTProbe = func(context.Context, string) error { return errors.New("must reuse active route") }
	engine := NewEngine(t.TempDir(), t.TempDir(), &fakeRunner{}, sharedResolverExtra{resolver: resolver}, nil)
	engine.probeServices = func(ctx context.Context, active *SmartDNS) []Target {
		if active != resolver {
			return []Target{{Name: "ChatGPT", Error: "different DNS resolver"}}
		}
		response := active.Resolve(ctx, query("chatgpt.com", 1))
		return []Target{{Name: "ChatGPT", OK: bytes.Equal(response, applicationReply), Route: active.preferredChatGPT()}}
	}
	if err := engine.Start(Config{Extras: true}, "", false, func(string) {}); err != nil {
		t.Fatal(err)
	}
	defer engine.Stop()
	deadline := time.Now().Add(2 * time.Second)
	for len(engine.Snapshot().Services) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	state := engine.Snapshot()
	if len(state.Services) != 1 || !state.Services[0].OK || state.Services[0].Route != "132.243.112.221" {
		t.Fatal("health did not validate the application's cached route", state)
	}
	for _, result := range ProbeExtrasWithDNS(context.Background(), nil) {
		if result.OK || result.Stage != "DNS" {
			t.Fatal("inactive resolver claimed success", result)
		}
	}
}

func TestChatGPTRouteUsesVerifiedTLSHostAndStrictPublicResponse(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"chatgpt.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	parsed, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	var status atomic.Int32
	status.Store(200)
	var body atomic.Value
	var challenged atomic.Bool
	body.Store(`{"openai":{"id":"openai","type":"oauth"}}`)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "chatgpt.com" || r.TLS.ServerName != "chatgpt.com" || r.URL.Path != "/api/auth/providers" {
			t.Error("wrong authenticated target", r.Host, r.TLS.ServerName, r.URL.Path)
		}
		if challenged.Load() {
			w.Header().Set("Cf-Mitigated", "challenge")
		}
		w.WriteHeader(int(status.Load()))
		w.Write([]byte(body.Load().(string)))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	client := newChatGPTRouteClient("132.243.112.221")
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	url := "https://chatgpt.com/api/auth/providers"
	if probeChatGPT(context.Background(), client, url) == nil {
		t.Fatal("untrusted certificate accepted")
	}
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if err := probeChatGPT(context.Background(), client, url); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{`{"openai":{"id":"other","type":"oauth"}}`, `{"openai":{"id":"openai","type":"password"}}`, string(bytes.Repeat([]byte("x"), 65537)), `<html>challenge</html>`} {
		body.Store(invalid)
		if probeChatGPT(context.Background(), client, url) == nil {
			t.Fatal("invalid public response accepted")
		}
	}
	body.Store(`{"openai":{"id":"openai","type":"oauth"}}`)
	challenged.Store(true)
	if probeChatGPT(context.Background(), client, url) == nil {
		t.Fatal("challenge header accepted")
	}
	challenged.Store(false)
	status.Store(403)
	if probeChatGPT(context.Background(), client, url) == nil {
		t.Fatal("HTTP403 accepted")
	}
}
