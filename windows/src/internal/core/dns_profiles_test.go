package core

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSCatalogRejectsUnsafeProfiles(t *testing.T) {
	for _, modify := range []func(*DNSProfile){
		func(p *DNSProfile) { p.URL = "http://dns.example.com/dns-query" },
		func(p *DNSProfile) { p.URL = "https://user:password@dns.example.com/dns-query" },
		func(p *DNSProfile) { p.URL = "https://localhost/dns-query" },
		func(p *DNSProfile) { p.Bootstrap = []string{"127.0.0.1"} },
		func(p *DNSProfile) { p.Bootstrap = []string{"192.168.1.2"} },
		func(p *DNSProfile) { p.Bootstrap = []string{"::1"} },
	} {
		c := LoadDNSCatalog("")
		modify(&c.Profiles[0])
		b, _ := json.Marshal(c)
		if _, err := ParseDNSCatalog(b); err == nil {
			t.Fatalf("unsafe profile accepted: %+v", c.Profiles[0])
		}
	}
}

func TestSelectedDNSProfileControlsActualResolverAndLeavesPublicDNSSeparate(t *testing.T) {
	resolver := NewSmartDNS(DomainRules{Builtin: true, DNSProfile: "geohide-eu"})
	defer resolver.Close()
	if resolver.profileURL != "https://eu.geohide.ru/dns-query" {
		t.Fatal(resolver.profileURL)
	}
	for _, endpoint := range resolver.public {
		if strings.Contains(endpoint.url, "geohide") {
			t.Fatal("regional DNS leaked to ordinary domains")
		}
	}
}

func TestDNSCatalogUpdateRetainsBundledSelection(t *testing.T) {
	directory := t.TempDir()
	catalog := LoadDNSCatalog("")
	catalog.Profiles = catalog.Profiles[:1]
	if err := SaveJSON(filepath.Join(directory, "dns-profiles.json"), catalog); err != nil {
		t.Fatal(err)
	}
	if chosen := FindDNSProfile(LoadDNSCatalog(directory), "malw"); chosen.ID != "malw" {
		t.Fatal("saved choice disappeared", chosen)
	}
}

func TestDNSMatrixClassifiesPublicResponsesWithoutFalseGeoblock(t *testing.T) {
	cases := []struct {
		service     string
		status      int
		headers     http.Header
		body, state string
	}{
		{"claude", 403, nil, "Forbidden", "denied"},
		{"claude", 403, nil, `{"error":{"code":"unsupported_country_region_territory"}}`, "regional_refusal"},
		{"claude", 200, http.Header{"Cf-Mitigated": []string{"challenge"}}, "", "challenge"},
		{"claude", 302, nil, "", "login_unchecked"},
		{"claude", 429, nil, "", "rate_limited"},
		{"claude", 200, nil, `<html><script>var error="This service is not available in your country";</script>Claude</html>`, "reachable_public"},
		{"chatgpt", 200, nil, "<html>OK</html>", "invalid_response"},
		{"chatgpt", 200, nil, `{"openai":{"id":"openai","type":"oauth"}}`, "reachable_public"},
	}
	for _, c := range cases {
		if actual := classifyDNSResponse(c.service, c.status, c.headers, []byte(c.body)); actual != c.state {
			t.Errorf("%d %s: %s", c.status, c.body, actual)
		}
	}
}

func TestDNSMatrixCancellationAndConcurrencyPreserveUnknownResults(t *testing.T) {
	var active, maximum atomic.Int32
	probe := func(ctx context.Context, p DNSProfile, s DNSService) DNSServiceResult {
		count := active.Add(1)
		defer active.Add(-1)
		for {
			old := maximum.Load()
			if count <= old || maximum.CompareAndSwap(old, count) {
				break
			}
		}
		<-ctx.Done()
		return DNSServiceResult{Service: s.ID, Name: s.Name, State: "timeout"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	report := scanDNSProfiles(ctx, LoadDNSCatalog(""), probe)
	if active.Load() != 0 || maximum.Load() > 8 {
		t.Fatal("probe lifecycle", active.Load(), maximum.Load())
	}
	if report.AccountChecked || report.SelectionChanged {
		t.Fatal("comparison changed configuration")
	}
	unknown := 0
	for _, p := range report.Profiles {
		for _, r := range p.Results {
			if r.State == "not_checked" {
				unknown++
			}
		}
	}
	if unknown == 0 {
		t.Fatal("queued requests incorrectly reported as checked")
	}
}
