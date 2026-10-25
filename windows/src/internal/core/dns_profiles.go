package core

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const DNSCatalogURL = "https://raw.githubusercontent.com/Def01d/SorryRKN/main/dns-profiles.json"

//go:embed dns_profiles.json
var bundledDNSCatalog []byte

type DNSProfile struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Bootstrap []string `json:"bootstrap"`
	Source    string   `json:"source"`
}
type DNSCatalog struct {
	Schema   int          `json:"schema"`
	Updated  string       `json:"updated"`
	Profiles []DNSProfile `json:"profiles"`
}

func ParseDNSCatalog(data []byte) (DNSCatalog, error) {
	var catalog DNSCatalog
	invalid := errors.New("invalid DNS catalog")
	if len(data) > 32768 || json.Unmarshal(data, &catalog) != nil || catalog.Schema != 1 || len(catalog.Profiles) < 1 || len(catalog.Profiles) > 12 {
		return catalog, invalid
	}
	seen := map[string]bool{}
	for _, p := range catalog.Profiles {
		u, err := url.Parse(p.URL)
		if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" && u.Port() != "443" || u.Path != "/dns-query" || u.RawQuery != "" || u.Fragment != "" ||
			!regexp.MustCompile(`^(?:[a-z0-9-]+\.)+[a-z]{2,}$`).MatchString(u.Hostname()) ||
			!regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`).MatchString(p.ID) || seen[p.ID] || len(p.Name) < 1 || len([]rune(p.Name)) > 60 || strings.IndexFunc(p.Name, unicode.IsControl) >= 0 || len(p.Bootstrap) > 4 {
			return catalog, invalid
		}
		seen[p.ID] = true
		for _, address := range p.Bootstrap {
			ip := net.ParseIP(address)
			if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
				return catalog, invalid
			}
		}
	}
	if !seen["comss"] {
		return catalog, invalid
	}
	return catalog, nil
}

func LoadDNSCatalog(directory string) DNSCatalog {
	catalog, _ := ParseDNSCatalog(bundledDNSCatalog)
	if data, err := os.ReadFile(filepath.Join(directory, "dns-profiles.json")); directory != "" && err == nil {
		payload, signatureError := VerifyEnvelope(data)
		if remote, err := ParseDNSCatalog(payload); err == nil && signatureError == nil {
			positions := map[string]int{}
			for i, p := range catalog.Profiles {
				positions[p.ID] = i
			}
			for _, p := range remote.Profiles {
				if i, ok := positions[p.ID]; ok {
					catalog.Profiles[i] = p
				} else {
					positions[p.ID] = len(catalog.Profiles)
					catalog.Profiles = append(catalog.Profiles, p)
				}
			}
			if len(catalog.Profiles) > 12 {
				catalog, _ = ParseDNSCatalog(bundledDNSCatalog)
			} else {
				catalog.Updated = remote.Updated
			}
		}
	}
	return catalog
}

func RefreshDNSCatalog(ctx context.Context, directory string) error {
	path := filepath.Join(directory, "dns-profiles.json")
	if info, err := os.Stat(path); err == nil && time.Since(info.ModTime()) < 24*time.Hour {
		return nil
	}
	body, err := Fetch(ctx, HTTPClient(), DNSCatalogURL, 32768)
	if err != nil {
		return err
	}
	payload, err := VerifyEnvelope(body)
	if err != nil {
		return err
	}
	catalog, err := ParseDNSCatalog(payload)
	if err != nil {
		return err
	}
	current := LoadDNSCatalog(directory)
	positions := map[string]int{}
	for i, p := range current.Profiles {
		positions[p.ID] = i
	}
	for _, p := range catalog.Profiles {
		if i, ok := positions[p.ID]; ok {
			current.Profiles[i] = p
		} else {
			positions[p.ID] = len(current.Profiles)
			current.Profiles = append(current.Profiles, p)
		}
	}
	if len(current.Profiles) > 12 {
		return errors.New("DNS catalog merge too large")
	}
	current.Updated = catalog.Updated
	return SaveJSON(path, json.RawMessage(body))
}

func FindDNSProfile(catalog DNSCatalog, identifier string) DNSProfile {
	for _, p := range catalog.Profiles {
		if p.ID == identifier {
			return p
		}
	}
	for _, p := range catalog.Profiles {
		if p.ID == "comss" {
			return p
		}
	}
	return DNSProfile{}
}

func NewProfileDNS(profile DNSProfile, rules DomainRules) *SmartDNS {
	host, _ := url.Parse(profile.URL)
	s := &SmartDNS{rules: rules, cache: make(map[string]cachedDNS), client: newDNSClient(host.Hostname(), ""), profileURL: profile.URL, profileID: profile.ID}
	for _, address := range profile.Bootstrap {
		s.fallbacks = append(s.fallbacks, newDNSClient(host.Hostname(), address))
	}
	for _, endpoint := range [][2]string{{"cloudflare-dns.com", "1.1.1.1"}, {"dns.google", "8.8.8.8"}, {"cloudflare-dns.com", "1.0.0.1"}, {"dns.google", "8.8.4.4"}} {
		s.public = append(s.public, dnsUpstream{url: "https://" + endpoint[0] + "/dns-query", client: newDNSClient(endpoint[0], endpoint[1])})
	}
	return s
}
