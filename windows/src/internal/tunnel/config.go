package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"sorryrkn/internal/core"
	"sorryrkn/internal/mirage"
)

type Options struct {
	ExcludedApps  []string
	DirectDomains []string
}

func processPathRegex(exe string) string {
	return `(?i)(?:^|[\\/])` + regexp.QuoteMeta(exe) + `$`
}

// Resolve only the tunnel gateway before installing any routes. Normal DNS is sent
// through the selected outbound. Preserve the original TLS/WS names when dialing an IP.
func configFor(ctx context.Context, p Profile, excludedApps ...string) (object, error) {
	return configForOptions(ctx, p, Options{ExcludedApps: excludedApps})
}

func configForOptions(ctx context.Context, p Profile, opts Options) (object, error) {
	dns := object{"type": "https", "server": "1.1.1.1", "tls": object{"server_name": "cloudflare-dns.com"}, "detour": "vpn", "tag": "remote"}
	cfg := object{}
	_, out, err := parseNode(p.Link)
	if err != nil {
		return nil, err
	}
	outboundType, _ := out["type"].(string)
	cfg["outbounds"] = []object{out}
	host := out["server"].(string)
	if transport, ok := out["transport"].(object); ok {
		switch transport["type"] {
		case "ws":
			if _, ok := transport["headers"]; !ok {
				transport["headers"] = object{"Host": host}
			}
		case "httpupgrade":
			if transport["host"] == "" {
				transport["host"] = host
			}
		case "http":
			if _, ok := transport["host"]; !ok {
				transport["host"] = []string{host}
			}
		}
	}
	ip, err := resolveGateway(ctx, host)
	if err != nil {
		return nil, err
	}
	out["server"] = ip.String()
	// The relay is advertised only after it has been provisioned on the VPS.
	// VLESS frames both TCP and UDP inside Chromium HTTPS CONNECT. The virtual
	// target is interpreted by the server's authenticated loopback gateway and
	// is never resolved or dialed on the client network.
	if outboundType == "naive" {
		u, _ := url.Parse(p.Link)
		if relay := u.Query().Get("relay"); relay != "" {
			out["tag"] = "https"
			cfg["outbounds"] = []object{{"type": "vless", "tag": "vpn", "server": "relay.sorryrkn.invalid", "server_port": 443, "uuid": relay, "detour": "https"}, out}
		}
	}
	excludes := []string{
		netip.PrefixFrom(ip, ip.BitLen()).String(),
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"fe80::/10",
	}
	tun := object{"type": "tun", "interface_name": "SorryRKN-Tunnel", "address": []string{"198.19.254.1/30", "fd7a:7272:6b6e:1::1/126"}, "auto_route": true, "strict_route": true, "dns_mode": "hijack", "mtu": 1360, "route_exclude_address": excludes}
	excluded, err := core.NormalizeExcludedApps(opts.ExcludedApps)
	if err != nil {
		return nil, err
	}
	directDomains, err := core.ParseDomains(strings.Join(opts.DirectDomains, "\n"))
	if err != nil {
		return nil, err
	}
	var excludedRegexes []string
	for _, exe := range excluded {
		excludedRegexes = append(excludedRegexes, processPathRegex(exe))
	}

	rules := []object{
		{"port": 53, "action": "hijack-dns"},
		{"ip_cidr": []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fe80::/10"}, "action": "route", "outbound": "direct"},
	}
	if len(excludedRegexes) > 0 {
		rules = append(rules, object{"process_path_regex": excludedRegexes, "action": "route", "outbound": "direct"})
	}
	if len(directDomains) > 0 {
		rules = append(rules,
			object{"action": "sniff"},
			object{"domain_suffix": directDomains, "action": "route", "outbound": "direct"},
		)
	}
	// Prevent HTTP/3 QUIC-over-TCP congestion collapse while keeping real UDP
	// (WebRTC voice, STUN, gaming) intact on TCP-based tunnels.
	if outboundType != "hysteria2" {
		rules = append(rules, object{"network": "udp", "port": 443, "action": "reject"})
	}

	dnsRules := []object{}
	if len(excludedRegexes) > 0 {
		dnsRules = append(dnsRules, object{"process_path_regex": excludedRegexes, "action": "route", "server": "direct-dns"})
	}
	dnsRules = append(dnsRules,
		object{"domain_suffix": []string{"local", "corp", "internal", "intranet", "lan", "home", "arpa", "localdomain"}, "action": "route", "server": "direct-dns"},
		object{"domain_regex": []string{"^[^.]+$"}, "action": "route", "server": "direct-dns"},
	)
	if len(directDomains) > 0 {
		dnsRules = append(dnsRules, object{"domain_suffix": directDomains, "action": "route", "server": "direct-dns"})
	}
	dnsRules = append(dnsRules,
		object{"action": "evaluate", "server": "remote"},
		object{"match_response": true, "response_rcode": "NXDOMAIN", "action": "route", "server": "direct-dns"},
		object{"match_response": true, "action": "respond"},
	)

	cfg["log"] = object{"level": "info"}
	cfg["inbounds"] = []object{tun}
	outs := cfg["outbounds"].([]object)
	cfg["outbounds"] = append(outs, object{"type": "direct", "tag": "direct"})
	cfg["dns"] = object{
		"servers": []object{
			dns,
			object{"type": "local", "tag": "direct-dns"},
		},
		"rules": dnsRules,
		"final": "remote",
	}
	routeBlock := object{
		"auto_detect_interface":   true,
		"default_domain_resolver": "direct-dns",
		"final":                   "vpn",
		"rules":                   rules,
	}
	if len(excludedRegexes) > 0 {
		routeBlock["find_process"] = true
	}
	cfg["route"] = routeBlock
	return cfg, nil
}
func resolveGateway(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	ips, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", host)
	cancel()
	if err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if ip.Is4() || ip.Is4In6() {
				return ip.Unmap(), nil
			}
		}
		return ips[0], nil
	}
	if ip, dohErr := resolveGatewayDoH(ctx, host); dohErr == nil {
		return ip, nil
	}
	return netip.Addr{}, errors.New("DNS не нашёл адрес VPN-сервера")
}
func resolveGatewayDoH(ctx context.Context, host string) (netip.Addr, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return netip.Addr{}, err
	}
	msg := dnsmessage.Message{Header: dnsmessage.Header{RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, err := msg.Pack()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, provider := range []struct{ host, ip string }{{"cloudflare-dns.com", "1.1.1.1"}, {"dns.google", "8.8.8.8"}} {
		tr := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 2 * time.Second, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(provider.ip, "443"))
		}}
		client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
		req, reqErr := http.NewRequestWithContext(ctx, "POST", "https://"+provider.host+"/dns-query", bytes.NewReader(wire))
		if reqErr != nil {
			tr.CloseIdleConnections()
			continue
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, doErr := client.Do(req)
		if doErr != nil {
			tr.CloseIdleConnections()
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		tr.CloseIdleConnections()
		if readErr != nil || resp.StatusCode != 200 {
			continue
		}
		var reply dnsmessage.Message
		if reply.Unpack(body) != nil || reply.RCode != dnsmessage.RCodeSuccess {
			continue
		}
		for _, ans := range reply.Answers {
			if a, ok := ans.Body.(*dnsmessage.AResource); ok {
				ip := netip.AddrFrom4(a.A)
				if ip.IsGlobalUnicast() && !ip.IsPrivate() {
					return ip, nil
				}
			}
		}
	}
	return netip.Addr{}, errors.New("DoH lookup failed")
}
func engineConfig(ctx context.Context, p Profile, excludedApps ...string) ([]byte, error) {
	return engineConfigOptions(ctx, p, Options{ExcludedApps: excludedApps})
}

func engineConfigOptions(ctx context.Context, p Profile, opts Options) ([]byte, error) {
	cfg, err := configForOptions(ctx, p, opts)
	if err != nil {
		return nil, err
	}
	return json.Marshal(cfg)
}

// attachMirageBridge launches an in-process authenticated SOCKS5 bridge for mirage://
// profiles and rewires cfg's primary outbound to point at the local bridge while keeping
// the already-resolved server IP in tun.route_exclude_address to prevent routing loops.
func attachMirageBridge(ctx context.Context, p Profile, cfg object) (*mirage.Client, error) {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(p.Link)), "mirage://") {
		return nil, nil
	}
	mc, err := mirage.ParseURI(p.Link)
	if err != nil {
		return nil, err
	}
	outbounds, _ := cfg["outbounds"].([]object)
	if len(outbounds) == 0 {
		return nil, errors.New("отсутствует outbound для Мираж")
	}
	if resolvedIP, ok := outbounds[0]["server"].(string); ok && net.ParseIP(resolvedIP) != nil {
		mc.ServerHost = resolvedIP
	}
	var cred [24]byte
	if _, err := rand.Read(cred[:]); err != nil {
		return nil, errors.New("не удалось создать учётные данные моста Мираж")
	}
	user := "m_" + hex.EncodeToString(cred[:8])
	pass := hex.EncodeToString(cred[8:])

	mc.ListenAddr = "127.0.0.1:0"
	mc.AuthUser = user
	mc.AuthPass = pass

	cli, err := mirage.NewClient(mc)
	if err != nil {
		return nil, err
	}
	addr, err := cli.Start(ctx)
	if err != nil {
		_ = cli.Close()
		return nil, err
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		_ = cli.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)
	outbounds[0] = object{
		"type":         "socks",
		"tag":          "vpn",
		"server":       host,
		"server_port":  port,
		"version":      "5",
		"username":     user,
		"password":     pass,
		"udp_over_tcp": false,
	}
	return cli, nil
}
