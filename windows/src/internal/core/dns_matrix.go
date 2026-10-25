package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type DNSService struct{ ID, Name, URL string }

var DNSServices = func() []DNSService {
	var out []DNSService
	for _, s := range ServiceDefinitions {
		out = append(out, DNSService{s.ID, s.Name, s.URL})
	}
	return out
}()

type DNSServiceResult struct {
	Service             string `json:"service"`
	Name                string `json:"name"`
	State               string `json:"state"`
	HTTPStatus          int    `json:"http_status,omitempty"`
	LatencyMS           int64  `json:"latency_ms,omitempty"`
	Address             string `json:"address,omitempty"`
	AuthenticatedAccess bool   `json:"authenticated_access"`
	CheckedAt           string `json:"checked_at,omitempty"`
}
type DNSProfileResult struct {
	ID      string             `json:"id"`
	Name    string             `json:"name"`
	Results []DNSServiceResult `json:"results"`
}
type DNSMatrix struct {
	CheckedAt        string             `json:"checked_at"`
	Scope            string             `json:"scope"`
	AccountChecked   bool               `json:"account_checked"`
	SelectionChanged bool               `json:"selection_changed"`
	NetworkKey       string             `json:"network_key,omitempty"`
	SelectionKey     string             `json:"selection_key,omitempty"`
	Coverage         string             `json:"coverage,omitempty"`
	Cached           bool               `json:"cached,omitempty"`
	Profiles         []DNSProfileResult `json:"profiles"`
}

var scripts = regexp.MustCompile(`(?is)<(script|style)\b[^>]*>.*?</(?:script|style)\s*>|<!--.*?-->`)
var tags = regexp.MustCompile(`<[^>]*>`)
var regionText = regexp.MustCompile(`(?i)\b(?:(?:your|this) (?:country|region) (?:is not supported|is unsupported)|(?:chatgpt|this service|openai(?:'s)?(?: services)?) (?:is|are) not available in your (?:country|region)|country,?\s*region,?\s*(?:or\s*)?territory\s+(?:is\s+)?not supported)\b`)

func classifyDNSResponse(service string, status int, headers http.Header, body []byte) string {
	visible := strings.Join(strings.Fields(html.UnescapeString(tags.ReplaceAllString(scripts.ReplaceAllString(string(body), " "), " "))), " ")
	var value map[string]json.RawMessage
	if json.Unmarshal(body, &value) == nil {
		raw := body
		if errorValue, ok := value["error"]; ok {
			raw = errorValue
		}
		var detail struct {
			Code    string `json:"code"`
			Type    string `json:"type"`
			Message string `json:"message"`
		}
		var code string
		json.Unmarshal(raw, &code)
		json.Unmarshal(raw, &detail)
		if code == "unsupported_country_region_territory" || detail.Code == "unsupported_country_region_territory" || detail.Type == "unsupported_country_region_territory" || regionText.MatchString(detail.Message) {
			return "regional_refusal"
		}
	} else if visible == "unsupported_country_region_territory" || regionText.MatchString(visible) {
		return "regional_refusal"
	}
	lower := strings.ToLower(string(body))
	text := strings.ToLower(visible)
	if strings.EqualFold(headers.Get("Cf-Mitigated"), "challenge") || (strings.Contains(lower, "cf-chl-") || strings.Contains(lower, "/cdn-cgi/challenge-platform/")) && (strings.Contains(text, "just a moment") || strings.Contains(text, "checking your browser") || strings.Contains(text, "verify you are human")) {
		return "challenge"
	}
	if status == 429 {
		return "rate_limited"
	}
	if status == 401 || status >= 300 && status < 400 {
		return "login_unchecked"
	}
	if status == 403 {
		return "denied"
	}
	if status != 200 {
		return "http_error"
	}
	if service == "chatgpt" {
		var providers map[string]struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}
		if json.Unmarshal(body, &providers) != nil || providers["openai"].ID != "openai" || providers["openai"].Type != "oauth" {
			return "invalid_response"
		}
	}
	return "reachable_public"
}

func dnsProfileAddresses(ctx context.Context, resolver *SmartDNS, host string) []string {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil
	}
	message := dnsmessage.Message{Header: dnsmessage.Header{RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	query, _ := message.Pack()
	var reply dnsmessage.Message
	if reply.Unpack(resolver.query(ctx, query, false)) != nil || reply.RCode != dnsmessage.RCodeSuccess {
		return nil
	}
	names := map[string]bool{host + ".": true}
	for range 16 {
		for _, rr := range reply.Answers {
			if cname, ok := rr.Body.(*dnsmessage.CNAMEResource); ok && names[strings.ToLower(rr.Header.Name.String())] {
				names[strings.ToLower(cname.CNAME.String())] = true
			}
		}
	}
	var addresses []string
	for _, rr := range reply.Answers {
		if address, ok := rr.Body.(*dnsmessage.AResource); ok && names[strings.ToLower(rr.Header.Name.String())] {
			ip := net.IP(address.A[:])
			if ip.IsGlobalUnicast() && !ip.IsPrivate() {
				addresses = append(addresses, ip.String())
				if len(addresses) == 3 {
					break
				}
			}
		}
	}
	return addresses
}

func ProbeDNSService(ctx context.Context, profile DNSProfile, service DNSService) DNSServiceResult {
	result := DNSServiceResult{Service: service.ID, Name: service.Name, State: "dns_error", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	resolver := NewProfileDNS(profile, DomainRules{})
	defer resolver.Close()
	target, _ := url.Parse(service.URL)
	addresses := dnsProfileAddresses(ctx, resolver, target.Hostname())
	for _, address := range addresses {
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 2 * time.Second,
			DialContext: func(ctx context.Context, network, destination string) (net.Conn, error) {
				if destination != target.Hostname()+":443" {
					return nil, errors.New("unexpected probe destination")
				}
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(address, "443"))
			}}
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, _ := http.NewRequestWithContext(ctx, "GET", service.URL, nil)
		req.Header.Set("User-Agent", "SorryRKN-DNSCheck")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Accept", "text/html, application/json")
		response, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 32768))
			response.Body.Close()
			result.Address = address
			result.HTTPStatus = response.StatusCode
			encoded := response.Header.Get("Content-Encoding")
			if readErr != nil {
				result.State = "transport_error"
			} else if encoded != "" && encoded != "identity" {
				result.State = "invalid_response"
			} else {
				result.State = classifyDNSResponse(service.ID, response.StatusCode, response.Header, body)
			}
		} else {
			result.State = "transport_error"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout") {
				result.State = "timeout"
			}
		}
		transport.CloseIdleConnections()
		if result.State == "reachable_public" || result.State == "login_unchecked" {
			break
		}
	}
	if ctx.Err() != nil {
		result.State = "timeout"
	}
	result.LatencyMS = time.Since(started).Milliseconds()
	return result
}

func ScanDNSProfiles(ctx context.Context, catalog DNSCatalog) DNSMatrix {
	return scanDNSProfiles(ctx, catalog, ProbeDNSService)
}
func scanDNSProfiles(ctx context.Context, catalog DNSCatalog, probe func(context.Context, DNSProfile, DNSService) DNSServiceResult) DNSMatrix {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	result := DNSMatrix{CheckedAt: time.Now().UTC().Format(time.RFC3339), Scope: "anonymous_public_https", NetworkKey: NetworkFingerprint(), Coverage: "full"}
	for _, p := range catalog.Profiles {
		row := DNSProfileResult{ID: p.ID, Name: p.Name}
		for _, s := range DNSServices {
			row.Results = append(row.Results, DNSServiceResult{Service: s.ID, Name: s.Name, State: "not_checked"})
		}
		result.Profiles = append(result.Profiles, row)
	}
	semaphore := make(chan struct{}, 8)
	var workers sync.WaitGroup
	for i, p := range catalog.Profiles {
		for j, s := range DNSServices {
			workers.Add(1)
			go func(i, j int, p DNSProfile, s DNSService) {
				defer workers.Done()
				if ctx.Err() != nil {
					return
				}
				select {
				case semaphore <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-semaphore }()
				if ctx.Err() != nil {
					return
				}
				result.Profiles[i].Results[j] = probe(ctx, p, s)
			}(i, j, p, s)
		}
	}
	workers.Wait()
	return result
}

func DNSStateLabel(state string) string {
	switch state {
	case "reachable_public":
		return "Страница доступна"
	case "login_unchecked":
		return "Вход не проверен"
	case "regional_refusal":
		return "Отказ по региону"
	case "challenge":
		return "Проверка браузера"
	case "denied":
		return "Отказ HTTP 403"
	case "rate_limited":
		return "Лимит запросов"
	case "dns_error":
		return "DNS не ответил"
	case "timeout":
		return "Тайм-аут"
	case "transport_error":
		return "Ошибка соединения"
	case "invalid_response":
		return "Ответ не подтверждён"
	case "http_error":
		return "Ошибка HTTP"
	default:
		return "Не проверено"
	}
}

func (m DNSMatrix) Text() string {
	var out strings.Builder
	fmt.Fprintf(&out, "Проверено: %s\r\nПубличные страницы; аккаунты не проверялись.\r\n", m.CheckedAt)
	if m.Cached {
		fmt.Fprintln(&out, "Результаты из кеша текущей сети.")
	}
	if m.Coverage == "selected" {
		fmt.Fprintln(&out, "Проверены выбранные маршруты. Полный перебор — кнопка «Проверить».")
	}
	if m.NetworkKey != "" && m.NetworkKey != NetworkFingerprint() {
		fmt.Fprintln(&out, "Результаты относятся к другой сети; повторите проверку.")
	}
	for _, p := range m.Profiles {
		fmt.Fprintf(&out, "\r\n%s\r\n", p.Name)
		for _, s := range p.Results {
			fmt.Fprintf(&out, "  %s: %s", s.Name, DNSStateLabel(s.State))
			if s.HTTPStatus != 0 {
				fmt.Fprintf(&out, " · %d", s.HTTPStatus)
			}
			if s.LatencyMS > 0 {
				fmt.Fprintf(&out, " · %d мс", s.LatencyMS)
			}
			fmt.Fprint(&out, "\r\n")
		}
	}
	return out.String()
}

func DNSStateHint(state string) string {
	switch state {
	case "challenge":
		return "Откройте сервис в браузере и пройдите проверку."
	case "login_unchecked":
		return "Страница отвечает; проверьте вход в своём браузере."
	case "regional_refusal":
		return "Выберите другой DNS или включите авто с резервом."
	case "rate_limited":
		return "Подождите перед повторной проверкой."
	case "denied":
		return "Причина HTTP 403 не подтверждена как геоблокировка."
	case "dns_error", "timeout", "transport_error":
		return "Повторите проверку или сравните другой DNS."
	case "invalid_response", "http_error":
		return "Ответ сервиса не подтверждает доступ; откройте диагностику."
	}
	return ""
}

func (m DNSMatrix) SelectedText(c Config, active []ServiceRouteStatus, catalog DNSCatalog) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Проверено: %s\r\nПубличные страницы; вход и генерация не проверены.\r\n", m.CheckedAt)
	current := map[string]string{}
	for _, route := range active {
		current[route.Service] = route.Profile
	}
	now := time.Now()
	valid := matrixFresh(m, now, NetworkFingerprint())
	for _, service := range ServiceDefinitions {
		mode := "по умолчанию"
		profile := c.ServiceDNS[service.ID]
		if profile == "auto" {
			mode = "авто с резервом"
			profile = bestServiceProfile(m, service.ID, FindDNSProfile(catalog, c.DNSProfile).ID, catalog, now)
		} else if profile == "" {
			profile = FindDNSProfile(catalog, c.DNSProfile).ID
		} else {
			mode = "закреплён"
		}
		fmt.Fprintf(&out, "\r\n%s · %s · %s\r\n", service.Name, mode, FindDNSProfile(catalog, profile).Name)
		if actual := current[service.ID]; actual != "" {
			fmt.Fprintf(&out, "  Активен: %s\r\n", FindDNSProfile(catalog, actual).Name)
			profile = actual
		}
		state := "not_checked"
		for _, row := range m.Profiles {
			if row.ID == profile {
				for _, cell := range row.Results {
					if cell.Service == service.ID && valid && cellFresh(m, cell, now) {
						state = cell.State
					}
				}
			}
		}
		fmt.Fprintf(&out, "  %s\r\n", DNSStateLabel(state))
		if hint := DNSStateHint(state); hint != "" {
			fmt.Fprintf(&out, "  %s\r\n", hint)
		}
	}
	if !valid {
		fmt.Fprintln(&out, "\r\nРезультаты отсутствуют, устарели или относятся к другой сети.")
	}
	return out.String()
}
