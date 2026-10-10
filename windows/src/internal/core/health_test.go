package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestAutomaticSearchContinuesAfterBrokenLastFastCandidate(t *testing.T) {
	root := t.TempDir()
	catalog := Catalog{Revision: "test"}
	for i := 0; i < 7; i++ {
		p := Profile{ID: fmt.Sprint(i), Name: fmt.Sprint(i), Args: []string{"--wf-tcp=443", "--wf-udp=443", "--filter-tcp=443"}}
		if i == 5 {
			p.Args = append(p.Args, "--hostlist=@LISTS@/missing.txt")
		}
		catalog.Profiles = append(catalog.Profiles, p)
	}
	if err := SaveJSON(filepath.Join(root, "zapret", "profiles.json"), catalog); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(root, t.TempDir(), &fakeRunner{}, fakeExtra{}, nil)
	e.probe = func(ctx context.Context, p string) Check {
		return Check{Profile: p, Targets: []Target{{Name: "YouTube", OK: p == "6"}, {Name: "Discord", OK: p == "6"}}}
	}
	if err := e.Start(Config{DPI: true, Method: "auto"}, "", false, func(string) {}); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	deadline := time.Now().Add(8 * time.Second)
	for e.Snapshot().Status == "starting" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	s := e.Snapshot()
	if s.Status != "on" || s.Profile != "6" {
		t.Fatalf("never reached extended working candidate: %+v", s)
	}
}

func TestTelegramHealthRequiresFreshProtocolEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "health.json")
	now := time.Now().UTC()
	if h := ReadTelegramHealth(path, now); h.State != "checking" {
		t.Fatal(h)
	}
	h := TelegramHealth{State: "ready", CheckedAt: now.Format(time.RFC3339Nano)}
	SaveJSON(path, h)
	if got := ReadTelegramHealth(path, now); got.State != "checking" {
		t.Fatal("bare readiness accepted", got)
	}
	h.Datacenters = map[string]TelegramDCHealth{"2": {OK: true}, "4": {OK: false}}
	SaveJSON(path, h)
	if got := ReadTelegramHealth(path, now); got.State != "degraded" {
		t.Fatal(got)
	}
	h.Datacenters["4"] = TelegramDCHealth{OK: true}
	SaveJSON(path, h)
	if got := ReadTelegramHealth(path, now); got.State != "ready" {
		t.Fatal(got)
	}
	if got := ReadTelegramHealth(path, now.Add(91*time.Second)); got.State != "checking" {
		t.Fatal("stale success accepted", got)
	}
	h.Datacenters["2"], h.Datacenters["4"] = TelegramDCHealth{}, TelegramDCHealth{}
	SaveJSON(path, h)
	if got := ReadTelegramHealth(path, now); got.State != "unavailable" {
		t.Fatal(got)
	}
}

func TestServiceHealthDoesNotConfuseListenerAndAvailability(t *testing.T) {
	s := State{Telegram: true, TelegramHealth: TelegramHealth{State: "unavailable"}}
	applyServiceHealth(&s, "on", "Работает в фоне")
	if s.Status != "partial" {
		t.Fatal(s)
	}
	s.TelegramHealth.State = "ready"
	s.Services = []Target{{Name: "ChatGPT", OK: false}}
	applyServiceHealth(&s, "on", "Работает в фоне")
	if s.Status != "partial" {
		t.Fatal(s)
	}
	s.Services[0].OK = true
	applyServiceHealth(&s, "on", "Работает в фоне")
	if s.Status != "on" {
		t.Fatal(s)
	}
	applyServiceHealth(&s, "partial", "DPI failed")
	if s.Status != "partial" || s.Detail != "DPI failed" {
		t.Fatal("masked DPI failure", s)
	}
}

func TestApplicationProbesRejectCaptivePortalAndRegionalDenial(t *testing.T) {
	for _, tc := range []struct {
		body string
		code int
		good bool
	}{
		{`{"openai":{"id":"openai","type":"oauth"}}`, 200, true},
		{`<html>blocked</html>`, 200, false},
		{`{"error":{"code":"unsupported_country_region_territory"}}`, 403, false},
		{`{"openai":{"id":"openai","type":"oauth"}}`, 403, false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.code); w.Write([]byte(tc.body)) }))
		err := probeChatGPT(context.Background(), srv.Client(), srv.URL)
		srv.Close()
		if (err == nil) != tc.good {
			t.Fatalf("code %d body %s: %v", tc.code, tc.body, err)
		}
	}
	for _, status := range []int{200, 204, 403} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		err := probe204(context.Background(), srv.Client(), srv.URL)
		srv.Close()
		if (err == nil) != (status == 204) {
			t.Fatalf("204 probe accepted status %d: %v", status, err)
		}
	}
}
