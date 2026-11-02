package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

func WireGuard(config string) (Profile, error) {
	_, _, err := wireGuardEndpoint(config)
	if err != nil {
		return Profile{}, err
	}
	return Profile{Name: "Свой сервер · WireGuard", Protocol: "wireguard", Link: config}, nil
}

func key32(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return true
		}
	}
	return false
}
func list(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
func prefixes(s string) ([]string, error) {
	parts := list(s)
	for _, part := range parts {
		if _, err := netip.ParsePrefix(part); err != nil {
			return nil, errors.New("неверная подсеть WireGuard")
		}
	}
	return parts, nil
}
func wireGuardEndpoint(config string) (object, string, error) {
	if len(config) > 32<<10 {
		return nil, "", errors.New("слишком большой профиль WireGuard")
	}
	iface := map[string]string{}
	peer := map[string]string{}
	var section map[string]string
	for _, line := range strings.Split(config, "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch line {
		case "[Interface]":
			if section != nil {
				return nil, "", errors.New("повтор раздела Interface")
			}
			section = iface
			continue
		case "[Peer]":
			if section == nil || len(peer) > 0 {
				return nil, "", errors.New("поддерживается один Peer")
			}
			section = peer
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || section == nil || section[k] != "" {
			return nil, "", errors.New("неверный профиль WireGuard")
		}
		switch k {
		case "Address", "PrivateKey", "DNS", "MTU", "PublicKey", "PresharedKey", "Endpoint", "AllowedIPs", "PersistentKeepalive":
		default:
			return nil, "", errors.New("неподдерживаемая настройка WireGuard")
		}
		section[k] = strings.TrimSpace(v)
	}
	if !key32(iface["PrivateKey"]) || !key32(peer["PublicKey"]) {
		return nil, "", errors.New("неверные ключи WireGuard")
	}
	address, err := prefixes(iface["Address"])
	if err != nil {
		return nil, "", err
	}
	allowed, err := prefixes(peer["AllowedIPs"])
	if err != nil {
		return nil, "", err
	}
	host, port, err := net.SplitHostPort(peer["Endpoint"])
	if err != nil {
		return nil, "", errors.New("неверный Endpoint WireGuard")
	}
	srv, err := server(host, port)
	if err != nil {
		return nil, "", err
	}
	remote := object{"address": host, "port": srv["server_port"], "public_key": peer["PublicKey"], "allowed_ips": allowed}
	if psk := peer["PresharedKey"]; psk != "" {
		if !key32(psk) {
			return nil, "", errors.New("неверный PSK WireGuard")
		}
		remote["pre_shared_key"] = psk
	}
	if ka := peer["PersistentKeepalive"]; ka != "" {
		n, err := strconv.ParseUint(ka, 10, 16)
		if err != nil {
			return nil, "", errors.New("неверный PersistentKeepalive")
		}
		remote["persistent_keepalive_interval"] = n
	}
	ep := object{"type": "wireguard", "tag": "vpn", "system": false, "address": address, "private_key": iface["PrivateKey"], "peers": []object{remote}}
	if mtu := iface["MTU"]; mtu != "" {
		n, err := strconv.ParseUint(mtu, 10, 16)
		if err != nil || n < 576 {
			return nil, "", errors.New("неверный MTU WireGuard")
		}
		ep["mtu"] = n
	}
	dns := ""
	if iface["DNS"] != "" {
		for _, v := range list(iface["DNS"]) {
			if net.ParseIP(v) != nil {
				dns = v
				break
			}
		}
		if dns == "" {
			return nil, "", errors.New("нужен IP DNS-сервера WireGuard")
		}
	}
	return ep, dns, nil
}

// Resolve only the tunnel gateway before installing any routes. Normal DNS is sent
// through the selected outbound. Preserve the original TLS/WS names when dialing an IP.
func configFor(ctx context.Context, p Profile) (object, error) {
	var outbound object
	var host string
	dns := object{"type": "https", "server": "1.1.1.1", "tls": object{"server_name": "cloudflare-dns.com"}, "detour": "vpn", "tag": "remote"}
	cfg := object{}
	if p.Protocol == "wireguard" {
		ep, wgDNS, err := wireGuardEndpoint(p.Link)
		if err != nil {
			return nil, err
		}
		cfg["endpoints"] = []object{ep}
		outbound = ep["peers"].([]object)[0]
		host = outbound["address"].(string)
		if wgDNS != "" {
			dns = object{"type": "udp", "server": wgDNS, "detour": "vpn", "tag": "remote"}
		}
	} else {
		_, out, err := parseNode(p.Link)
		if err != nil {
			return nil, err
		}
		outbound = out
		cfg["outbounds"] = []object{out}
		host = out["server"].(string)
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
	}
	ip, err := resolveGateway(ctx, host)
	if err != nil {
		return nil, err
	}
	if p.Protocol == "wireguard" {
		outbound["address"] = ip.String()
	} else {
		outbound["server"] = ip.String()
	}
	tun := object{"type": "tun", "interface_name": "SorryRKN-Tunnel", "address": []string{"172.31.254.1/30", "fd7a:7272:6b6e:1::1/126"}, "auto_route": true, "strict_route": true, "dns_mode": "hijack", "mtu": 1400, "route_exclude_address": []string{netip.PrefixFrom(ip, ip.BitLen()).String()}}
	cfg["log"] = object{"level": "info"}
	cfg["inbounds"] = []object{tun}
	cfg["dns"] = object{"servers": []object{dns}, "final": "remote"}
	cfg["route"] = object{"auto_detect_interface": true, "final": "vpn", "rules": []object{{"port": 53, "action": "hijack-dns"}}}
	return cfg, nil
}
func resolveGateway(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, errors.New("DNS не нашёл адрес VPN-сервера")
	}
	for _, ip := range ips {
		if ip.Is4() || ip.Is4In6() {
			return ip.Unmap(), nil
		}
	}
	return ips[0], nil
}
func engineConfig(ctx context.Context, p Profile) ([]byte, error) {
	cfg, err := configFor(ctx, p)
	if err != nil {
		return nil, err
	}
	return json.Marshal(cfg)
}
