package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestUserDomainNormalization(t *testing.T) {
	domains, e := ParseDomains(" HTTPS://Example.COM:443/path?q=1\r\n*.example.com\nпример.рф\n api.example.net. \n")
	if e != nil || !reflect.DeepEqual(domains, []string{"example.com", "xn--e1afmkfd.xn--p1ai", "api.example.net"}) {
		t.Fatal(domains, e)
	}
	for _, text := range []string{"http://user:password@example.com/", "file:///tmp/x", "127.0.0.1", "[::1]", "example..com", "-example.com", "example.com & calc.exe", "https://example.com:0/", "https://example.com:65536/", "localhost", "example.com\n--dpi-desync=fake", strings.Repeat("x", MaxDomainText+1)} {
		if _, e = ParseDomains(text); e == nil {
			t.Fatal("accepted invalid input", text[:min(len(text), 100)])
		}
	}
	var many strings.Builder
	for i := 0; i < MaxDomains+1; i++ {
		many.WriteString(strings.Repeat("x", i/63+1) + "." + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example.com\n")
	}
	if _, e = ParseDomains(many.String()); e == nil {
		t.Fatal("accepted too many domains")
	}
}
func TestUserDirectWinsOverGeoAndBuiltin(t *testing.T) {
	r := DomainRules{Geo: []string{"example.com", "chatgpt.com"}, Direct: []string{"private.example.com", "chatgpt.com"}, Builtin: true}
	for _, host := range []string{"chatgpt.com", "API.CHATGPT.COM.", "private.example.com", "a.private.example.com"} {
		if !r.IsDirect(host) || r.IsGeo(host) {
			t.Fatal(host)
		}
		if NewSmartDNS(r).Resolve(context.Background(), query(host, 28)) != nil {
			t.Fatal("direct DNS intercepted", host)
		}
	}
	for _, host := range []string{"example.com", "api.example.com", "claude.ai"} {
		if !r.IsGeo(host) {
			t.Fatal(host)
		}
		response := NewSmartDNS(r).Resolve(context.Background(), query(host, 65))
		if len(response) == 0 || response[3]&15 != 0 {
			t.Fatal(host, response)
		}
	}
	for _, host := range []string{"evil-example.com", "example.com.evil.test", "unrelated.test"} {
		if r.IsGeo(host) || r.IsDirect(host) {
			t.Fatal(host)
		}
	}
	custom := DomainRules{Geo: []string{"example.com"}}
	if custom.IsGeo("chatgpt.com") || !custom.IsGeo("api.example.com") {
		t.Fatal("disabled builtins leaked")
	}
}
func TestUserRulesPersistAndWinwsNoopHasPriority(t *testing.T) {
	dir := t.TempDir()
	c := DefaultConfig()
	c.GeoDomains = []string{"example.com"}
	c.DirectDomains = []string{"bank.example.com"}
	c.ProtectedSecret = "existing-dpapi-secret"
	path := filepath.Join(dir, "config.json")
	if e := SaveJSON(path, c); e != nil {
		t.Fatal(e)
	}
	loaded := LoadConfig(path)
	if !reflect.DeepEqual(c, loaded) {
		t.Fatal("settings lost", loaded)
	}
	r, e := loaded.Rules()
	if e != nil {
		t.Fatal(e)
	}
	list, e := WriteBypassList(dir, r)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(list)
	args := WithDirect(WithInstagram([]string{"--wf-tcp=443", "--wf-udp=443", "--filter-tcp=443", "--dpi-desync=fake", "--new", "--filter-udp=443", "--dpi-desync=fake"}, "instagram.txt"), list)
	first := strings.Index(strings.Join(args, " "), "--new")
	if !strings.Contains(strings.Join(args, " ")[:first], "--hostlist="+list) || strings.Contains(strings.Join(args, " ")[:first], "dpi-desync") {
		t.Fatal("direct did not win", args)
	}
	// Simulate replacement of downloaded data; preferences and user materialization remain separate.
	snapshot := filepath.Join(dir, "snapshots", "new", "lists")
	os.MkdirAll(snapshot, 0700)
	os.WriteFile(filepath.Join(snapshot, "list-exclude-user.txt"), []byte("downloaded.test\n"), 0600)
	after, _ := os.ReadFile(list)
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(c, LoadConfig(path)) {
		t.Fatal("downloaded snapshot changed user rules")
	}
}

func TestMaximumListsMaterializeTogether(t *testing.T) {
	r := DomainRules{Builtin: true}
	for i := 0; i < MaxDomains; i++ {
		r.Geo = append(r.Geo, fmt.Sprintf("geo%d.example.com", i))
		r.Direct = append(r.Direct, fmt.Sprintf("direct%d.example.com", i))
	}
	p, e := WriteBypassList(t.TempDir(), r)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(p)
	if e != nil || len(strings.Fields(string(b))) != MaxDomains*2+len(AIHosts) {
		t.Fatal("maximum lists not accepted together", e)
	}
}
