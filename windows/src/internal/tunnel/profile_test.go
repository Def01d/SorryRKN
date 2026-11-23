package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"sorryrkn/internal/mirage"
)

const fakeUUID = "137001ca-1c37-4f48-a2d3-3d72253b051c"

func samples() []string {
	ss := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:example-pass"))
	vm := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"add":"127.0.0.1","port":"12345","id":"%s","aid":"0","net":"ws","tls":"tls","sni":"example.org","path":"/test","ps":"Fixture"}`, fakeUUID)))
	key := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("A", 32)))
	spki := base64.StdEncoding.EncodeToString(make([]byte, 32))
	sec, pin, _, _, _ := mirage.GenerateCredentials("edge.example.org")
	return []string{
		"vless://" + fakeUUID + "@127.0.0.1:12345?security=reality&pbk=" + key + "&sid=0123&sni=example.org&fp=chrome&flow=xtls-rprx-vision#Reality",
		"vless://" + fakeUUID + "@127.0.0.1:12345?type=grpc&serviceName=test&security=tls#GRPC",
		"vmess://" + vm, "trojan://abc@127.0.0.1:12345?sni=example.org&type=ws&path=/test",
		"ss://" + ss + "@127.0.0.1:12345#Example",
		"hy2://pass@127.0.0.1:12345?sni=example.org&obfs=salamander&obfs-password=obfs&spki=" + spki,
		"mirage://" + sec + "@127.0.0.1:443?sni=edge.example.org&pin=" + pin + "#MirageTest",
	}
}

func TestMixedSubscription(t *testing.T) {
	input := append(samples(), "vless://"+fakeUUID+"@127.0.0.1:443?type=xhttp", "ss://invalid", "trojan://test@127.0.0.1:12345?allowInsecure=1", samples()[0])
	encoded := base64.RawURLEncoding.EncodeToString([]byte(strings.Join(input, "\n")))
	result, err := ImportWithReport(context.Background(), encoded)
	if err != nil || result.Skipped != 3 || len(result.Profiles) != len(samples()) {
		t.Fatalf("mixed subscription: %+v %v", result, err)
	}
	for _, p := range result.Profiles {
		cfg, err := configFor(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		if p.Protocol == "mirage" {
			bridge, err := attachMirageBridge(context.Background(), p, cfg)
			if err != nil {
				t.Fatalf("attachMirageBridge: %v", err)
			}
			_ = bridge.Close()
		}
		if p.Protocol == "hysteria2" {
			outs := cfg["outbounds"].([]object)
			tlsCfg := outs[0]["tls"].(object)
			if _, ok := tlsCfg["certificate_public_key_sha256"]; !ok {
				t.Fatalf("expected certificate_public_key_sha256 on pinned hy2")
			}
		}
	}
	_ = sha256.Size
}

func TestConfigForExcludedApps(t *testing.T) {
	p, _, err := parseNode("vless://" + fakeUUID + "@127.0.0.1:12345?encryption=none#Test")
	if err != nil {
		t.Fatal(err)
	}
	base, err := configFor(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	routeBase := base["route"].(object)
	if _, hasFind := routeBase["find_process"]; hasFind {
		t.Fatalf("expected no find_process when excluded apps list is empty")
	}
	if routeBase["default_domain_resolver"] != "direct-dns" {
		t.Fatalf("expected base default_domain_resolver=direct-dns, got %v", routeBase["default_domain_resolver"])
	}
	tunBase := base["inbounds"].([]object)[0]
	tunAddr := tunBase["address"].([]string)
	if tunAddr[0] != "198.19.254.1/30" {
		t.Fatalf("expected non-overlapping TUN IPv4 198.19.254.1/30, got %v", tunAddr)
	}
	tunExcludes := tunBase["route_exclude_address"].([]string)
	hasCorp172 := false
	for _, cidr := range tunExcludes {
		if cidr == "172.16.0.0/12" {
			hasCorp172 = true
		}
	}
	if !hasCorp172 {
		t.Fatalf("missing 172.16.0.0/12 in route_exclude_address: %v", tunExcludes)
	}

	withApps, err := configForOptions(context.Background(), p, Options{
		ExcludedApps:  []string{`"C:\Users\alice\AppData\Local\Programs\eXpress\eXpress.exe"`, "discord", "express.exe"},
		DirectDomains: []string{"corp.example.ru", "EXPRESS.COMPANY"},
	})
	if err != nil {
		t.Fatal(err)
	}
	route := withApps["route"].(object)
	if route["find_process"] != true || route["default_domain_resolver"] != "direct-dns" {
		t.Fatalf("expected find_process=true and default_domain_resolver=direct-dns, got %v / %v", route["find_process"], route["default_domain_resolver"])
	}
	rules := route["rules"].([]object)
	if len(rules) < 6 || rules[0]["action"] != "hijack-dns" || rules[1]["outbound"] != "direct" || rules[2]["outbound"] != "direct" || rules[3]["action"] != "sniff" || rules[4]["outbound"] != "direct" {
		t.Fatalf("unexpected route rule order: %+v", rules)
	}
	gotRegexes, _ := rules[2]["process_path_regex"].([]string)
	if len(gotRegexes) != 2 {
		t.Fatalf("expected 2 deduplicated process_path_regex entries, got %v", gotRegexes)
	}
	rxExpress := regexp.MustCompile(gotRegexes[1]) // sorted: discord.exe, express.exe
	if !rxExpress.MatchString(`C:\Users\alice\AppData\Local\Programs\eXpress\eXpress.exe`) ||
		!rxExpress.MatchString(`EXPRESS.EXE`) ||
		!rxExpress.MatchString(`express.exe`) ||
		rxExpress.MatchString(`C:\Tools\myexpress.exe`) {
		t.Fatalf("unexpected process_path_regex matching for %q", gotRegexes[1])
	}
	if !reflect.DeepEqual(rules[4]["domain_suffix"], []string{"corp.example.ru", "express.company"}) {
		t.Fatalf("unexpected direct domain_suffix: %v", rules[4]["domain_suffix"])
	}

	dnsCfg := withApps["dns"].(object)
	dnsRules := dnsCfg["rules"].([]object)
	if len(dnsRules) != 7 {
		t.Fatalf("expected 7 dns rules (process, corp suffixes, short hostname, direct domains, evaluate, nxdomain, respond), got %d: %+v", len(dnsRules), dnsRules)
	}
	if _, ok := dnsRules[0]["process_path_regex"]; !ok || dnsRules[0]["server"] != "direct-dns" {
		t.Fatalf("unexpected first dns rule: %+v", dnsRules[0])
	}
	if dnsRules[4]["action"] != "evaluate" || dnsRules[5]["response_rcode"] != "NXDOMAIN" || dnsRules[6]["action"] != "respond" {
		t.Fatalf("unexpected split-horizon NXDOMAIN fallback chain: %+v", dnsRules[4:])
	}
	outs := withApps["outbounds"].([]object)
	if outs[len(outs)-1]["tag"] != "direct" {
		t.Fatalf("missing direct outbound: %+v", outs)
	}
}
