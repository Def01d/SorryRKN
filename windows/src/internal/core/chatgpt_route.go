package core

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const chatGPTRouteTTL = 120 * time.Second

type chatGPTRoute struct {
	address string
	expires time.Time
}

// Only a fixed anonymous request selects a route. Neither user TLS nor user
// HTTP requests are inspected, replayed or used as discovery probes.
func checkChatGPTRoute(ctx context.Context, address string) error {
	client := newChatGPTRouteClient(address)
	defer client.CloseIdleConnections()
	return probeChatGPT(ctx, client, "https://chatgpt.com/api/auth/providers")
}

func newChatGPTRouteClient(address string) *http.Client {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 2 * time.Second,
		DialContext: func(ctx context.Context, network, requested string) (net.Conn, error) {
			if requested != "chatgpt.com:443" {
				return nil, errors.New("unexpected route probe target")
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(address, "443"))
		}}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("route probe redirect rejected") }}
	// The original URL supplies both HTTP Host and TLS ServerName. The transport
	// only substitutes the TCP destination and uses the system trust store.
	return client
}

func chatGPTAddresses(message dnsmessage.Message) []string {
	names := map[string]bool{"chatgpt.com.": true}
	for range 16 {
		changed := false
		for _, rr := range message.Answers {
			if cname, ok := rr.Body.(*dnsmessage.CNAMEResource); ok && names[strings.ToLower(rr.Header.Name.String())] {
				name := strings.ToLower(cname.CNAME.String())
				if !names[name] {
					names[name] = true
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	var addresses []string
	seen := map[string]bool{}
	for _, rr := range message.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok && names[strings.ToLower(rr.Header.Name.String())] {
			ip := net.IP(a.A[:])
			if ip.IsGlobalUnicast() && !ip.IsPrivate() && !seen[ip.String()] {
				seen[ip.String()] = true
				addresses = append(addresses, ip.String())
				if len(addresses) == 4 {
					break
				}
			}
		}
	}
	return addresses
}

func (s *SmartDNS) preferredChatGPT() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Now().Before(s.chatGPTRoute.expires) {
		return s.chatGPTRoute.address
	}
	return ""
}

func (s *SmartDNS) preferChatGPT(ctx context.Context, host string, typ uint16, packet []byte) []byte {
	if host != "chatgpt.com" || typ != uint16(dnsmessage.TypeA) || !s.rules.IsGeo(host) {
		return packet
	}
	var message dnsmessage.Message
	if message.Unpack(packet) != nil || message.RCode != dnsmessage.RCodeSuccess {
		return packet
	}
	// A failed selection must not leave an unverified relay in the application's
	// DNS cache for the upstream's much longer TTL. Keep the whole answer, but
	// permit clients to request a newly verified route after the negative cache.
	fallback := func() []byte {
		for _, section := range [][]dnsmessage.Resource{message.Answers, message.Authorities, message.Additionals} {
			for i := range section {
				if section[i].Header.Type != dnsmessage.TypeOPT {
					section[i].Header.TTL = min(section[i].Header.TTL, 15)
				}
			}
		}
		if result, err := message.Pack(); err == nil && len(result) <= 4096 {
			return result
		}
		return packet
	}
	addresses := chatGPTAddresses(message)
	if len(addresses) < 2 {
		return fallback()
	}
	contains := func(address string) bool {
		for _, candidate := range addresses {
			if candidate == address {
				return true
			}
		}
		return false
	}
	var preferred string
	for {
		if ctx.Err() != nil {
			return fallback()
		}
		s.mu.Lock()
		cached := s.chatGPTRoute
		if time.Now().Before(cached.expires) && (cached.address == "" || contains(cached.address)) {
			preferred = cached.address
			s.mu.Unlock()
			break
		}
		if pending := s.chatGPTFlight; pending != nil {
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				return fallback()
			case <-pending:
				continue
			}
		}
		pending := make(chan struct{})
		s.chatGPTFlight = pending
		s.mu.Unlock()
		preferred = s.selectChatGPTRoute(ctx, addresses)
		s.mu.Lock()
		if ctx.Err() == nil {
			ttl := chatGPTRouteTTL
			if preferred == "" {
				ttl = 15 * time.Second
			}
			s.chatGPTRoute = chatGPTRoute{preferred, time.Now().Add(ttl)}
		}
		s.chatGPTFlight = nil
		close(pending)
		s.mu.Unlock()
		break
	}
	if preferred == "" {
		return fallback()
	}
	// Returning only the verified A record prevents clients randomizing across
	// challenge-only addresses. DNS authentication cannot survive an edited RRset.
	message.AuthenticData = false
	filter := func(records []dnsmessage.Resource) []dnsmessage.Resource {
		out := make([]dnsmessage.Resource, 0, len(records))
		for _, rr := range records {
			if rr.Header.Type == dnsmessage.Type(46) {
				continue
			} // RRSIG
			if a, ok := rr.Body.(*dnsmessage.AResource); ok && net.IP(a.A[:]).String() != preferred {
				continue
			}
			if rr.Header.Type != dnsmessage.TypeOPT {
				rr.Header.TTL = min(rr.Header.TTL, 30)
			}
			out = append(out, rr)
		}
		return out
	}
	message.Answers = filter(message.Answers)
	message.Authorities = filter(message.Authorities)
	message.Additionals = filter(message.Additionals)
	result, err := message.Pack()
	if err != nil || len(result) > 4096 {
		return packet
	}
	return result
}

func (s *SmartDNS) selectChatGPTRoute(ctx context.Context, addresses []string) string {
	if ctx.Err() != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	probe := s.chatGPTProbe
	if probe == nil {
		probe = checkChatGPTRoute
	}
	results := make(chan string, len(addresses))
	var pending sync.WaitGroup
	for _, address := range addresses {
		pending.Add(1)
		go func(address string) {
			defer pending.Done()
			// Relays can return a valid response once and a browser challenge on
			// the next connection. Confirm with a fresh TLS connection within the
			// same overall deadline before pinning the DNS answer.
			if probe(ctx, address) == nil && probe(ctx, address) == nil {
				results <- address
			} else {
				results <- ""
			}
		}(address)
	}
	defer func() { cancel(); pending.Wait() }()
	for range addresses {
		select {
		case <-ctx.Done():
			return ""
		case address := <-results:
			if address != "" {
				return address
			}
		}
	}
	return ""
}
