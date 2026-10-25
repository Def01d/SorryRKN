package core

import (
	"context"
	"golang.org/x/net/dns/dnsmessage"
	"path/filepath"
	"testing"
	"time"
)

func TestServiceRoutesUseDifferentProvidersAndRespectDirectExceptions(t *testing.T) {
	s := NewSmartDNS(DomainRules{Builtin: true, ServiceDNS: map[string]string{"chatgpt": "geohide-eu", "gemini": "malw"}, Direct: []string{"direct.chatgpt.com"}})
	defer s.Close()
	var got []string
	for _, id := range []string{"geohide-eu", "malw"} {
		child := NewProfileDNS(FindDNSProfile(LoadDNSCatalog(""), id), s.rules)
		child.fallbacks = nil
		child.client = testDNSClient(func(q []byte) []byte { host, _, _, _ := Question(q); got = append(got, host); return dnsAnswer(q, 30) })
		// ChatGPT's public route check is tested separately; use Gemini/Claude here.
		child.chatGPTProbe = func(context.Context, string) error { return nil }
		s.serviceDNS[id] = child
	}
	s.Resolve(context.Background(), query("api.openai.com", 1))
	s.Resolve(context.Background(), query("gemini.google.com", 1))
	if len(got) != 2 || got[0] != "api.openai.com" || got[1] != "gemini.google.com" {
		t.Fatal(got)
	}
	if s.Resolve(context.Background(), query("direct.chatgpt.com", 1)) != nil {
		t.Fatal("direct exception used relay")
	}
	if s.serviceDNS["geohide-eu"].profileURL == s.serviceDNS["malw"].profileURL {
		t.Fatal("providers not separated")
	}
}

func TestServiceGroupingIncludesAuthAndRejectsLookalikes(t *testing.T) {
	for host, want := range map[string]string{"auth.openai.com": "chatgpt", "cdn.workos.com": "chatgpt", "GEMINI.GOOGLE.COM.": "gemini", "notebooklm.google.com": "notebooklm", "chatgpt.com.evil.example": "", "challenges.cloudflare.com": ""} {
		if got := ServiceForHost(host); got != want {
			t.Fatalf("%s: %s", host, got)
		}
	}
}

func TestAutoDNSCapsClientCacheLifetime(t *testing.T) {
	s := NewSmartDNS(DomainRules{Builtin: true, ServiceDNS: map[string]string{"gemini": "auto"}})
	defer s.Close()
	child := NewProfileDNS(FindDNSProfile(LoadDNSCatalog(""), "comss"), s.rules)
	child.fallbacks = nil
	child.client = testDNSClient(func(q []byte) []byte { return dnsAnswer(q, 600) })
	s.serviceDNS["comss"] = child
	packet := s.Resolve(context.Background(), query("gemini.google.com", 1))
	if ttl := dnsCacheTTL(packet); ttl > 30*time.Second || ttl == 0 {
		t.Fatalf("invalid DNS TTL %s", ttl)
	}
	// Check the wire TTL too, not only the resolver's private cache duration.
	var answer dnsmessage.Message
	if answer.Unpack(packet) != nil || answer.Answers[0].Header.TTL > 30 {
		t.Fatal("client cache was not capped")
	}
}

func TestServiceAutoNeedsFreshMatchingNetworkAndRetainsWorkingExit(t *testing.T) {
	c := LoadDNSCatalog("")
	now := time.Now()
	m := DNSMatrix{CheckedAt: now.Format(time.RFC3339), NetworkKey: NetworkFingerprint(), Profiles: []DNSProfileResult{
		{ID: "geohide", Results: []DNSServiceResult{{Service: "chatgpt", State: "reachable_public"}}},
		{ID: "comss", Results: []DNSServiceResult{{Service: "chatgpt", State: "reachable_public"}}},
	}}
	if got := bestServiceProfile(m, "chatgpt", "comss", c, now); got != "comss" {
		t.Fatal("working exit changed", got)
	}
	m.Profiles[1].Results[0].State = "regional_refusal"
	if got := bestServiceProfile(m, "chatgpt", "comss", c, now); got != "geohide" {
		t.Fatal(got)
	}
	m.NetworkKey = "another network"
	if got := bestServiceProfile(m, "chatgpt", "comss", c, now); got != "comss" {
		t.Fatal("cross-network cache reused")
	}
	m.NetworkKey = NetworkFingerprint()
	m.CheckedAt = now.Add(-time.Hour).Format(time.RFC3339)
	if got := bestServiceProfile(m, "chatgpt", "comss", c, now); got != "comss" {
		t.Fatal("expired cache reused")
	}
}

func TestRecoveryRequiresTwoFailuresAndNeverChangesManualRoute(t *testing.T) {
	p := NewServiceRouter(DomainRules{ServiceDNS: map[string]string{"chatgpt": "auto", "gemini": "malw"}})
	calls := 0
	p.probe = func(_ context.Context, profile DNSProfile, s DNSService) DNSServiceResult {
		calls++
		if s.ID != "chatgpt" {
			t.Error("manual route probed for switching")
		}
		state := "transport_error"
		if profile.ID != "comss" {
			state = "reachable_public"
		}
		return DNSServiceResult{State: state}
	}
	p.Recover(context.Background())
	if p.Profile("chatgpt") != "comss" {
		t.Fatal("single failure switched exit")
	}
	p.checked = time.Now().Add(-time.Minute - 1)
	p.Recover(context.Background())
	if p.Profile("chatgpt") == "comss" || p.Profile("gemini") != "malw" {
		t.Fatal(p.Snapshot())
	}
	before := calls
	p.Recover(context.Background())
	if calls != before {
		t.Fatal("probe cooldown ignored")
	}
	p.checked = time.Now().Add(-time.Minute - 1)
	p.probe = func(context.Context, DNSProfile, DNSService) DNSServiceResult {
		return DNSServiceResult{State: "challenge"}
	}
	previous := p.Profile("chatgpt")
	p.Recover(context.Background())
	if p.Profile("chatgpt") != previous {
		t.Fatal("challenge rotated exit")
	}
}

func TestStartupCacheIncludesConfigurationAndIsBounded(t *testing.T) {
	dir := t.TempDir()
	c := DefaultConfig()
	m := DNSMatrix{CheckedAt: time.Now().Format(time.RFC3339), NetworkKey: NetworkFingerprint(), SelectionKey: DNSSelectionKey(c), Coverage: "full", Profiles: []DNSProfileResult{{ID: "comss", Results: []DNSServiceResult{{Service: "chatgpt", State: "reachable_public"}}}}}
	if err := SaveJSON(filepath.Join(dir, "dns-scan.json"), m); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := CheckConfiguredDNS(ctx, c, LoadDNSCatalog(""), dir, false)
	if !result.Cached || result.CheckedAt != m.CheckedAt {
		t.Fatal("disk cache not used")
	}
	if err := ValidateServiceDNS(map[string]string{"chatgpt": "https://evil.example"}); err == nil {
		t.Fatal("invalid setting accepted")
	}
	if err := ValidateServiceDNS(map[string]string{"unknown": "comss"}); err == nil {
		t.Fatal("unknown service accepted")
	}
	c.ServiceDNS = map[string]string{"chatgpt": "malw"}
	rules, err := c.Rules()
	if err != nil || rules.ServiceDNS["chatgpt"] != "malw" {
		t.Fatal(rules, err)
	}
}
