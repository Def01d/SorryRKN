// Package tunnel imports proxy node links into a deliberately restricted configuration.
// The engine only receives network options assembled here. Subscriptions cannot supply
// inbound listeners, routing rules, commands, files or a controller.
package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type object = map[string]any
type Profile struct {
	Name     string
	Protocol string
	Link     string
}
type Source struct {
	ManagedID string
	Name      string
	URL       string
	Profiles  []Profile
}
type Library struct {
	Sources        []Source
	SelectedSource int
	SelectedNode   int
}
type ImportResult struct {
	Profiles []Profile
	Skipped  int
}

const maxSubscription = 2 << 20
const maxNodes = 512

func decoded(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("неверный Base64")
}

func label(raw, fallback string) string {
	clean := strings.Join(strings.FieldsFunc(raw, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }), " ")
	clean = strings.TrimSpace(clean)
	if clean == "" {
		clean = fallback
	}
	runes := []rune(clean)
	if len(runes) > 100 {
		clean = string(runes[:100])
	}
	return clean
}

func download(ctx context.Context, input string) (string, error) {
	u, err := url.ParseRequestURI(input)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return "", errors.New("нужен HTTPS-адрес подписки")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", errors.New("неверный адрес подписки")
	}
	req.Header.Set("User-Agent", "SorryRKN/Windows")
	client := http.Client{Timeout: 20 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		r.Header.Del("Referer")
		if len(via) > 4 || r.URL.Scheme != "https" || r.URL.User != nil {
			return errors.New("недопустимое перенаправление")
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("не удалось загрузить подписку по HTTPS")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("сервер подписки вернул HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscription+1))
	if err != nil || len(b) > maxSubscription {
		return "", errors.New("слишком большой или неполный ответ подписки")
	}
	return string(b), nil
}

func Import(ctx context.Context, input string) ([]Profile, error) {
	result, err := ImportWithReport(ctx, input)
	return result.Profiles, err
}
func ImportWithReport(ctx context.Context, input string) (ImportResult, error) {
	var result ImportResult
	input = strings.TrimSpace(input)
	if len(input) > maxSubscription {
		return result, errors.New("подписка превышает 2 МиБ")
	}
	if strings.HasPrefix(input, "https://") && !strings.ContainsAny(input, "\r\n") {
		body, err := download(ctx, input)
		if err != nil {
			return result, err
		}
		input = strings.TrimSpace(body)
	}
	input = strings.TrimPrefix(input, "\uFEFF")
	if !strings.Contains(input, "://") {
		b, err := decoded(input)
		if err == nil {
			input = string(b)
		}
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		if len(line) > 32<<10 {
			result.Skipped++
			continue
		}
		p, _, err := parseNode(line)
		if err != nil {
			result.Skipped++
			continue
		}
		if len(result.Profiles) >= maxNodes {
			return ImportResult{}, errors.New("лимит подписки — 512 узлов")
		}
		result.Profiles = append(result.Profiles, p)
		seen[line] = true
	}
	if len(result.Profiles) == 0 {
		return result, errors.New("нет поддерживаемых узлов VLESS, VMess, Trojan, Shadowsocks или Hysteria2")
	}
	return result, nil
}

var uuid = regexp.MustCompile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

func validServer(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\[]%") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, part := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if part == "" || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, r := range part {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}
func server(host, port string) (object, error) {
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 || !validServer(host) {
		return nil, errors.New("неверный адрес узла")
	}
	return object{"server": host, "server_port": uint16(n), "tag": "vpn"}, nil
}
func parseNode(line string) (Profile, object, error) {
	empty := Profile{}
	scheme, _, ok := strings.Cut(line, "://")
	if !ok {
		return empty, nil, errors.New("нужна ссылка на узел")
	}
	if scheme == "vmess" {
		return parseVMess(line)
	}
	if scheme == "ss" {
		return parseSS(line)
	}
	if scheme != "vless" && scheme != "trojan" && scheme != "hy2" && scheme != "hysteria2" {
		return empty, nil, errors.New("неподдерживаемый тип узла")
	}
	u, err := url.Parse(line)
	if err != nil || u.User == nil {
		return empty, nil, errors.New("неверная ссылка узла")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return empty, nil, errors.New("неверные параметры узла")
	}
	port := u.Port()
	if port == "" && (scheme == "hy2" || scheme == "hysteria2") {
		port = "443"
	}
	out, err := server(u.Hostname(), port)
	if err != nil {
		return empty, nil, err
	}
	credential := u.User.Username()
	if suffix, has := u.User.Password(); has {
		credential += ":" + suffix
	}
	if credential == "" {
		return empty, nil, errors.New("пустые данные подключения")
	}
	security := q.Get("security")
	out["type"] = scheme
	switch scheme {
	case "vless":
		if !uuid.MatchString(credential) || (q.Get("encryption") != "" && q.Get("encryption") != "none") {
			return empty, nil, errors.New("неподдерживаемые параметры VLESS")
		}
		out["uuid"] = credential
		if flow := q.Get("flow"); flow != "" {
			if flow != "xtls-rprx-vision" {
				return empty, nil, errors.New("неизвестный VLESS flow")
			}
			out["flow"] = flow
		}
	case "trojan":
		out["password"] = credential
		if security == "" {
			security = "tls"
		}
	case "hy2", "hysteria2":
		out["type"] = "hysteria2"
		out["password"] = credential
		security = "tls"
		if q.Get("mport") != "" {
			return empty, nil, errors.New("диапазон портов Hysteria2 не поддерживается")
		}
		if obfs := q.Get("obfs"); obfs != "" {
			if obfs != "salamander" || q.Get("obfs-password") == "" {
				return empty, nil, errors.New("неподдерживаемый obfs")
			}
			out["obfs"] = object{"type": obfs, "password": q.Get("obfs-password")}
		}
	}
	if err := applyTLS(out, security, q, u.Hostname()); err != nil {
		return empty, nil, err
	}
	if err := applyTransport(out, q); err != nil {
		return empty, nil, err
	}
	return Profile{Name: label(u.Fragment, u.Hostname()), Protocol: out["type"].(string), Link: line}, out, nil
}

func applyTLS(out object, security string, q url.Values, host string) error {
	for _, key := range []string{"allowInsecure", "insecure", "allow_insecure", "skip-cert-verify"} {
		v := q.Get(key)
		if v != "" && v != "0" && !strings.EqualFold(v, "false") {
			return errors.New("отключение проверки сертификата не поддерживается")
		}
	}
	if security == "" || security == "none" {
		return nil
	}
	if security != "tls" && security != "reality" {
		return errors.New("неподдерживаемый TLS-режим")
	}
	name := q.Get("sni")
	if name == "" {
		name = host
	}
	tls := object{"enabled": true, "server_name": name}
	if fp := q.Get("fp"); fp != "" {
		tls["utls"] = object{"enabled": true, "fingerprint": fp}
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if security == "reality" {
		key, err := base64.RawURLEncoding.DecodeString(q.Get("pbk"))
		if err != nil || len(key) != 32 {
			return errors.New("неверный открытый ключ REALITY")
		}
		if _, ok := tls["utls"]; !ok {
			tls["utls"] = object{"enabled": true, "fingerprint": "chrome"}
		}
		tls["reality"] = object{"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid")}
	}
	out["tls"] = tls
	return nil
}

func applyTransport(out object, q url.Values) error {
	t := q.Get("type")
	host := q.Get("host")
	path := q.Get("path")
	switch t {
	case "", "tcp", "raw":
		if header := q.Get("headerType"); header != "" && header != "none" {
			return errors.New("неподдерживаемый заголовок TCP")
		}
		return nil
	case "ws":
		transport := object{"type": "ws", "path": path}
		if host != "" {
			transport["headers"] = object{"Host": host}
		}
		out["transport"] = transport
	case "grpc":
		if q.Get("mode") == "multi" {
			return errors.New("gRPC multi не поддерживается")
		}
		out["transport"] = object{"type": "grpc", "service_name": q.Get("serviceName")}
	case "h2", "http":
		transport := object{"type": "http", "path": path}
		if host != "" {
			transport["host"] = strings.Split(host, ",")
		}
		out["transport"] = transport
	case "httpupgrade":
		out["transport"] = object{"type": "httpupgrade", "host": host, "path": path}
	default:
		return errors.New("неподдерживаемый транспорт")
	}
	return nil
}

func parseVMess(line string) (Profile, object, error) {
	empty := Profile{}
	b, err := decoded(strings.TrimPrefix(line, "vmess://"))
	if err != nil {
		return empty, nil, err
	}
	var raw map[string]json.RawMessage
	if err = json.Unmarshal(b, &raw); err != nil {
		return empty, nil, errors.New("неверный VMess JSON")
	}
	field := func(k string) string {
		var s string
		if json.Unmarshal(raw[k], &s) == nil {
			return s
		}
		return strings.TrimSpace(string(raw[k]))
	}
	host := field("add")
	out, err := server(host, field("port"))
	if err != nil {
		return empty, nil, err
	}
	if !uuid.MatchString(field("id")) {
		return empty, nil, errors.New("неверный UUID VMess")
	}
	out["type"] = "vmess"
	out["uuid"] = field("id")
	sec := field("scy")
	if sec == "" {
		sec = "auto"
	}
	out["security"] = sec
	if aid := field("aid"); aid != "" {
		n, err := strconv.ParseUint(aid, 10, 16)
		if err != nil {
			return empty, nil, errors.New("неверный alterId")
		}
		out["alter_id"] = n
	}
	q := url.Values{"type": {field("net")}, "headerType": {field("type")}, "host": {field("host")}, "path": {field("path")}, "serviceName": {field("path")}, "sni": {field("sni")}, "fp": {field("fp")}, "alpn": {field("alpn")}, "allowInsecure": {field("allowInsecure")}}
	if err = applyTransport(out, q); err != nil {
		return empty, nil, err
	}
	if err = applyTLS(out, field("tls"), q, host); err != nil {
		return empty, nil, err
	}
	return Profile{Name: label(field("ps"), host), Protocol: "vmess", Link: line}, out, nil
}

func parseSS(line string) (Profile, object, error) {
	empty := Profile{}
	u, err := url.Parse(line)
	if err != nil || u.User == nil {
		raw, name, _ := strings.Cut(strings.TrimPrefix(line, "ss://"), "#")
		b, err := decoded(raw)
		if err != nil {
			return empty, nil, errors.New("неверная ссылка Shadowsocks")
		}
		user, addr, ok := strings.Cut(string(b), "@")
		if !ok {
			return empty, nil, errors.New("неверная ссылка Shadowsocks")
		}
		u, err = url.Parse("ss://" + base64.RawURLEncoding.EncodeToString([]byte(user)) + "@" + addr + "#" + name)
		if err != nil {
			return empty, nil, errors.New("неверный адрес Shadowsocks")
		}
	}
	if u.User == nil || u.Query().Get("plugin") != "" {
		return empty, nil, errors.New("плагины Shadowsocks не поддерживаются")
	}
	out, err := server(u.Hostname(), u.Port())
	if err != nil {
		return empty, nil, err
	}
	method := u.User.Username()
	password, ok := u.User.Password()
	if !ok {
		b, err := decoded(method)
		if err != nil {
			return empty, nil, err
		}
		method, password, ok = strings.Cut(string(b), ":")
	}
	if !ok || password == "" {
		return empty, nil, errors.New("пустые данные Shadowsocks")
	}
	switch method {
	case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
	default:
		return empty, nil, errors.New("неподдерживаемый метод Shadowsocks")
	}
	out["type"] = "shadowsocks"
	out["method"] = method
	out["password"] = password
	return Profile{Name: label(u.Fragment, u.Hostname()), Protocol: "shadowsocks", Link: line}, out, nil
}
