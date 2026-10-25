package core

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var dnsProfileID = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

//go:embed services.json
var servicesJSON []byte

type ServiceDefinition struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	Domains []string `json:"domains"`
}

var ServiceDefinitions = func() []ServiceDefinition {
	var c struct {
		Schema   int                 `json:"schema"`
		Services []ServiceDefinition `json:"services"`
	}
	if json.Unmarshal(servicesJSON, &c) != nil || c.Schema != 1 || len(c.Services) != 8 {
		panic("invalid bundled services")
	}
	return c.Services
}()

func ServiceDomains() []string {
	var result []string
	for _, s := range ServiceDefinitions {
		result = append(result, s.Domains...)
	}
	var extra struct {
		Shared []string `json:"shared_domains"`
	}
	json.Unmarshal(servicesJSON, &extra)
	return append(result, extra.Shared...)
}

func ServiceForHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	best, id := 0, ""
	for _, s := range ServiceDefinitions {
		for _, d := range s.Domains {
			if (host == d || strings.HasSuffix(host, "."+d)) && len(d) > best {
				best, id = len(d), s.ID
			}
		}
	}
	return id
}

func ValidateServiceDNS(values map[string]string) error {
	known := map[string]bool{}
	for _, s := range ServiceDefinitions {
		known[s.ID] = true
	}
	if len(values) > len(known) {
		return fmt.Errorf("слишком много маршрутов сервисов")
	}
	for id, p := range values {
		if !known[id] || p != "" && p != "auto" && !dnsProfileID.MatchString(p) {
			return fmt.Errorf("неверный DNS-маршрут сервиса %s", id)
		}
	}
	return nil
}

// This local fingerprint is a cache boundary, never an account/ISP identifier.
// A cached answer remains only a hint: automatic startup probes validate it.
func NetworkFingerprint() string {
	var values []string
	interfaces, _ := net.Interfaces()
	for _, i := range interfaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			values = append(values, i.Name+"/"+a.String())
		}
	}
	sort.Strings(values)
	sum := sha256.Sum256([]byte(strings.Join(values, "\n")))
	return hex.EncodeToString(sum[:16])
}

const DNSResultTTL = 30 * time.Minute

func matrixFresh(m DNSMatrix, now time.Time, network string) bool {
	t, e := time.Parse(time.RFC3339, m.CheckedAt)
	return e == nil && m.NetworkKey == network && !t.After(now.Add(time.Minute)) && now.Sub(t) < DNSResultTTL
}
func LoadDNSMatrix(directory string) DNSMatrix {
	var m DNSMatrix
	b, e := os.ReadFile(filepath.Join(directory, "dns-scan.json"))
	if e == nil && len(b) <= 131072 {
		if json.Unmarshal(b, &m) != nil {
			return DNSMatrix{}
		}
	}
	return m
}
func cellScore(c DNSServiceResult) int {
	switch c.State {
	case "reachable_public":
		return 2
	case "login_unchecked":
		return 1
	}
	return 0
}
func cellFresh(m DNSMatrix, c DNSServiceResult, now time.Time) bool {
	when := c.CheckedAt
	if when == "" {
		when = m.CheckedAt
	}
	t, e := time.Parse(time.RFC3339, when)
	return e == nil && !t.After(now.Add(time.Minute)) && now.Sub(t) < DNSResultTTL
}
func bestServiceProfile(m DNSMatrix, id, preferred string, catalog DNSCatalog, now time.Time) string {
	if !matrixFresh(m, now, NetworkFingerprint()) {
		return preferred
	}
	known := map[string]bool{}
	for _, p := range catalog.Profiles {
		known[p.ID] = true
	}
	best, score := preferred, 0
	// Retain a working current provider instead of chasing marginal latency.
	for _, row := range m.Profiles {
		for _, c := range row.Results {
			if c.Service == id && known[row.ID] && cellFresh(m, c, now) {
				n := cellScore(c)
				if n > score || n > 0 && n == score && row.ID == preferred {
					best, score = row.ID, n
				}
			}
		}
	}
	return best
}

type ServiceRouteStatus struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	Mode    string `json:"mode"`
	Profile string `json:"profile"`
	State   string `json:"state,omitempty"`
	Changes int    `json:"changes"`
}
type serviceRoute struct {
	profile           string
	failures, changes int
	changed           time.Time
	state             string
}
type ServiceRouter struct {
	mu        sync.Mutex
	modes     map[string]string
	enabled   map[string]bool
	routes    map[string]serviceRoute
	catalog   DNSCatalog
	defaultID string
	checked   time.Time
	checking  bool
	cooldowns map[string]time.Time
	probe     func(context.Context, DNSProfile, DNSService) DNSServiceResult
}

func NewServiceRouter(r DomainRules) *ServiceRouter {
	catalog := LoadDNSCatalog(r.DNSDirectory)
	fallback := FindDNSProfile(catalog, r.DNSProfile).ID
	m := LoadDNSMatrix(r.DNSDirectory)
	p := &ServiceRouter{modes: map[string]string{}, enabled: map[string]bool{}, routes: map[string]serviceRoute{}, catalog: catalog, defaultID: fallback, probe: ProbeDNSService, cooldowns: map[string]time.Time{}}
	for _, s := range ServiceDefinitions {
		p.enabled[s.ID] = r.IsGeo(s.Domains[0])
		mode := r.ServiceDNS[s.ID]
		id := fallback
		if mode == "auto" {
			id = bestServiceProfile(m, s.ID, fallback, catalog, time.Now())
		} else if mode != "" {
			id = FindDNSProfile(catalog, mode).ID
		}
		p.modes[s.ID] = mode
		p.routes[s.ID] = serviceRoute{profile: id}
	}
	return p
}
func (p *ServiceRouter) Profile(id string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.routes[id].profile
}
func (p *ServiceRouter) Snapshot() []ServiceRouteStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []ServiceRouteStatus
	for _, s := range ServiceDefinitions {
		r := p.routes[s.ID]
		mode := p.modes[s.ID]
		if mode == "" {
			mode = "default"
		} else if mode != "auto" {
			mode = "manual"
		}
		out = append(out, ServiceRouteStatus{s.ID, s.Name, mode, r.profile, r.state, r.changes})
	}
	return out
}

// Recover uses fixed anonymous probes only. It never sees or replays app TLS.
// Two failures and a cooldown prevent transient errors from rotating exits.
func (p *ServiceRouter) Recover(ctx context.Context) {
	p.mu.Lock()
	if p.checking || time.Since(p.checked) < time.Minute {
		p.mu.Unlock()
		return
	}
	p.checking = true
	p.checked = time.Now()
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.checking = false; p.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	slots := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, s := range DNSServices {
		p.mu.Lock()
		enabled := p.modes[s.ID] == "auto" && p.enabled[s.ID]
		p.mu.Unlock()
		if !enabled {
			continue
		}
		wg.Add(1)
		go func(s DNSService) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-slots }()
			p.mu.Lock()
			old := p.routes[s.ID]
			p.mu.Unlock()
			result := p.probe(ctx, FindDNSProfile(p.catalog, old.profile), s)
			if ctx.Err() != nil {
				return
			}
			p.mu.Lock()
			r := p.routes[s.ID]
			r.state = result.State
			if cellScore(result) > 0 || result.State == "challenge" || result.State == "rate_limited" {
				r.failures = 0
				p.routes[s.ID] = r
				p.mu.Unlock()
				return
			}
			r.failures++
			p.routes[s.ID] = r
			p.mu.Unlock()
			if r.failures < 2 || !r.changed.IsZero() && time.Since(r.changed) < 5*time.Minute {
				return
			}
			for _, candidate := range p.catalog.Profiles {
				if candidate.ID == old.profile || ctx.Err() != nil {
					continue
				}
				key := s.ID + "/" + candidate.ID
				p.mu.Lock()
				skip := time.Now().Before(p.cooldowns[key])
				p.mu.Unlock()
				if skip {
					continue
				}
				next := p.probe(ctx, candidate, s)
				if cellScore(next) > 0 && ctx.Err() == nil {
					p.mu.Lock()
					p.routes[s.ID] = serviceRoute{profile: candidate.ID, state: next.State, changes: r.changes + 1, changed: time.Now()}
					p.mu.Unlock()
					return
				}
				p.mu.Lock()
				p.cooldowns[key] = time.Now().Add(5 * time.Minute)
				p.mu.Unlock()
				return // One alternative per cycle keeps every service within budget.
			}
		}(s)
	}
	wg.Wait()
}

// Startup checks at most one configured route per service; full scans are manual.
func CheckConfiguredDNS(ctx context.Context, c Config, catalog DNSCatalog, directory string, force bool) DNSMatrix {
	key := NetworkFingerprint()
	old := LoadDNSMatrix(directory)
	if !force && matrixCacheFresh(old, time.Now(), key) && (old.Coverage == "full" || old.SelectionKey == DNSSelectionKey(c)) {
		old.Cached = true
		return old
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	m := DNSMatrix{CheckedAt: time.Now().UTC().Format(time.RFC3339), Scope: "anonymous_public_https", NetworkKey: key, Coverage: "selected", SelectionKey: DNSSelectionKey(c)}
	for _, p := range catalog.Profiles {
		row := DNSProfileResult{ID: p.ID, Name: p.Name}
		for _, s := range DNSServices {
			row.Results = append(row.Results, DNSServiceResult{Service: s.ID, Name: s.Name, State: "not_checked"})
		}
		m.Profiles = append(m.Profiles, row)
	}
	slots := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for j, s := range DNSServices {
		wg.Add(1)
		go func(j int, s DNSService) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-slots }()
			id := c.ServiceDNS[s.ID]
			if id == "" {
				id = c.DNSProfile
			}
			if id == "auto" {
				id = bestServiceProfile(old, s.ID, FindDNSProfile(catalog, c.DNSProfile).ID, catalog, time.Now())
			}
			p := FindDNSProfile(catalog, id)
			cell := ProbeDNSService(ctx, p, s)
			mu.Lock()
			for i := range m.Profiles {
				if m.Profiles[i].ID == p.ID {
					m.Profiles[i].Results[j] = cell
				}
			}
			mu.Unlock()
		}(j, s)
	}
	wg.Wait()
	return m
}

func matrixCacheFresh(m DNSMatrix, now time.Time, network string) bool {
	if !matrixFresh(m, now, network) {
		return false
	}
	checked, good := 0, 0
	for _, row := range m.Profiles {
		for _, cell := range row.Results {
			if cell.State != "not_checked" {
				checked++
				if cellScore(cell) > 0 {
					good++
				}
			}
		}
	}
	if m.Coverage == "full" && checked == len(m.Profiles)*len(DNSServices) && checked > 0 {
		return true
	}
	if checked >= len(DNSServices) && good >= len(DNSServices) {
		return true
	}
	when, _ := time.Parse(time.RFC3339, m.CheckedAt)
	return now.Sub(when) < 2*time.Minute
}

func DNSSelectionKey(c Config) string {
	b, _ := json.Marshal(struct {
		Default  string
		Services map[string]string
	}{c.DNSProfile, c.ServiceDNS})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:16])
}
