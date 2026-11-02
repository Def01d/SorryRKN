package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"time"
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
