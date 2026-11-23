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
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"sorryrkn/internal/mirage"
)

// Resolve only the tunnel gateway before installing any routes. Normal DNS is sent
// through the selected outbound. Preserve the original TLS/WS names when dialing an IP.
func configFor(ctx context.Context, p Profile) (object, error) {
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
		"192.168.0.0/16",
		"169.254.0.0/16",
		"224.0.0.0/4",
	}
	tun := object{"type": "tun", "interface_name": "SorryRKN-Tunnel", "address": []string{"172.31.254.1/30", "fd7a:7272:6b6e:1::1/126"}, "auto_route": true, "strict_route": true, "dns_mode": "hijack", "mtu": 1360, "route_exclude_address": excludes}
	rules := []object{{"port": 53, "action": "hijack-dns"}}
	// Prevent HTTP/3 QUIC-over-TCP congestion collapse while keeping real UDP
	// (WebRTC voice, STUN, gaming) intact on TCP-based tunnels.
	if outboundType != "hysteria2" {
		rules = append(rules, object{"network": "udp", "port": 443, "action": "reject"})
	}
	cfg["log"] = object{"level": "info"}
	cfg["inbounds"] = []object{tun}
	cfg["dns"] = object{"servers": []object{dns}, "final": "remote"}
	cfg["route"] = object{"auto_detect_interface": true, "final": "vpn", "rules": rules}
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
func engineConfig(ctx context.Context, p Profile) ([]byte, error) {
	cfg, err := configFor(ctx, p)
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
