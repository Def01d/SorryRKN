package core

import (
	"errors"
	"fmt"
	"golang.org/x/net/idna"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

const MaxDomainText = 32768
const MaxDomains = 256

var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var domainIDNA = idna.New(idna.MapForLookup(), idna.Transitional(true), idna.StrictDomainName(true), idna.ValidateLabels(true))

func ParseDomains(text string) ([]string, error) {
	if len([]rune(text)) > MaxDomainText {
		return nil, errors.New("список слишком длинный")
	}
	result := []string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		value := strings.TrimSpace(line)
		if value == "" {
			continue
		}
		value = strings.TrimPrefix(value, "*.")
		invalid := func() ([]string, error) { return nil, fmt.Errorf("неверный домен: %.80s", value) }
		if strings.IndexFunc(value, unicode.IsSpace) >= 0 || strings.Contains(value, "\\") {
			return invalid()
		}
		raw := value
		if !strings.Contains(raw, "://") {
			raw = "//" + raw
		}
		u, e := url.Parse(raw)
		if e != nil || u.User != nil || u.Hostname() == "" || u.Scheme != "" && !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
			return invalid()
		}
		if port := u.Port(); port != "" {
			number, e := strconv.Atoi(port)
			if e != nil || number < 1 || number > 65535 {
				return invalid()
			}
		}
		host, e := domainIDNA.ToASCII(strings.TrimSuffix(u.Hostname(), "."))
		host = strings.ToLower(host)
		if e != nil || net.ParseIP(host) != nil || len(host) > 253 || !strings.Contains(host, ".") {
			return invalid()
		}
		for _, label := range strings.Split(host, ".") {
			if !domainLabel.MatchString(label) {
				return invalid()
			}
		}
		if !seen[host] {
			result = append(result, host)
			seen[host] = true
		}
		if len(result) > MaxDomains {
			return nil, errors.New("не больше 256 доменов в каждом списке")
		}
	}
	if len(strings.Join(result, "\n")) > MaxDomainText {
		return nil, errors.New("список доменов после преобразования слишком длинный")
	}
	return result, nil
}

type DomainRules struct {
	Geo     []string
	Direct  []string
	Builtin bool
	Secure  bool
}

func MatchDomains(host string, domains []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
func (r DomainRules) IsDirect(host string) bool { return MatchDomains(host, r.Direct) }
func (r DomainRules) IsGeo(host string) bool {
	return !r.IsDirect(host) && (MatchDomains(host, r.Geo) || r.Builtin && IsAI(host))
}
func (r DomainRules) ShouldResolveDNS(host string) bool {
	return !r.IsDirect(host) && (r.IsGeo(host) || r.Secure && MatchDomains(host, ProtectedDNSHosts))
}
func (c Config) Rules() (DomainRules, error) {
	geo, e := ParseDomains(strings.Join(c.GeoDomains, "\n"))
	if e != nil {
		return DomainRules{}, e
	}
	direct, e := ParseDomains(strings.Join(c.DirectDomains, "\n"))
	if e != nil {
		return DomainRules{}, e
	}
	return DomainRules{Geo: geo, Direct: direct, Builtin: c.Extras, Secure: c.DPI || c.Telegram || c.Extras}, nil
}
func WriteBypassList(data string, r DomainRules) (string, error) {
	hosts := append(append([]string{}, r.Direct...), r.Geo...)
	if r.Builtin {
		hosts = append(hosts, AIHosts...)
	}
	seen := map[string]bool{}
	unique := []string{}
	for _, host := range hosts {
		if !seen[host] {
			unique = append(unique, host)
			seen[host] = true
		}
	}
	hosts = unique
	if len(hosts) == 0 {
		return "", nil
	}
	if e := os.MkdirAll(data, 0700); e != nil {
		return "", e
	}
	path := filepath.Join(data, "user-no-desync.txt")
	if e := os.WriteFile(path, []byte(strings.Join(hosts, "\n")+"\n"), 0600); e != nil {
		return "", e
	}
	return path, nil
}

// First matching winws profile forwards unchanged; it outranks all desync rules.
func WithDirect(args []string, list string) []string {
	if list == "" {
		return args
	}
	global, profiles := []string{}, []string{}
	for _, arg := range args {
		if strings.HasPrefix(arg, "--wf-") {
			global = append(global, arg)
		} else {
			profiles = append(profiles, arg)
		}
	}
	out := append(global, "--filter-tcp=1-65535", "--filter-udp=1-65535", "--hostlist="+list, "--new")
	return append(out, profiles...)
}
