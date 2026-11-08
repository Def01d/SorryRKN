package tunnel

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/url"
)

// Cronet accepts a private trust certificate directly for this one connection.
// It performs the hostname and TLS chain checks. No roots are installed into Windows.
func parseNaive(line string) (Profile, object, error) {
	var empty Profile
	u, err := url.Parse(line)
	if err != nil || u.User == nil {
		return empty, nil, errors.New("неверная ссылка HTTPS CONNECT")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return empty, nil, errors.New("неверные параметры HTTPS CONNECT")
	}
	for k, values := range q {
		if len(values) != 1 || values[0] == "" {
			return empty, nil, errors.New("пустой или повторяющийся параметр HTTPS CONNECT")
		}
		switch k {
		case "sni", "ca", "spki", "relay":
		default:
			return empty, nil, errors.New("неподдерживаемый параметр HTTPS CONNECT")
		}
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	out, err := server(u.Hostname(), port)
	if err != nil {
		return empty, nil, err
	}
	username := u.User.Username()
	password, ok := u.User.Password()
	if !ok || username == "" || password == "" {
		return empty, nil, errors.New("нужны логин и пароль HTTPS CONNECT")
	}
	name := q.Get("sni")
	if name == "" {
		name = u.Hostname()
	}
	if !validServer(name) {
		return empty, nil, errors.New("неверное имя TLS-сервера")
	}
	tls := object{"enabled": true, "server_name": name}
	if raw := q.Get("ca"); raw != "" {
		der, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil || len(der) > 16<<10 {
			return empty, nil, errors.New("неверный сертификат HTTPS CONNECT")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return empty, nil, errors.New("неверный сертификат HTTPS CONNECT")
		}
		if fingerprint := q.Get("spki"); fingerprint != "" {
			expected, err := decoded(fingerprint)
			actual := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if err != nil || subtle.ConstantTimeCompare(expected, actual[:]) != 1 {
				return empty, nil, errors.New("отпечаток не совпал с сертификатом HTTPS CONNECT")
			}
		}
		tls["certificate"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	} else if q.Has("spki") {
		return empty, nil, errors.New("для проверки отпечатка нужен сертификат HTTPS CONNECT")
	}
	out["type"] = "naive"
	out["username"] = username
	out["password"] = password
	out["tls"] = tls
	// Standard Caddy forwardproxy carries TCP CONNECT. Declaring UDP-over-TCP
	// would send UDP payloads to a private protocol the server does not implement.
	out["udp_over_tcp"] = false
	if relay := q.Get("relay"); relay != "" && !uuid.MatchString(relay) {
		return empty, nil, errors.New("неверный идентификатор HTTPS TCP/UDP")
	}
	return Profile{Name: label(u.Fragment, u.Hostname()), Protocol: "naive", Link: line}, out, nil
}
