// Package selfhost provisions the server selected by the user over pinned SSH.
package selfhost

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

//go:embed provision.sh
var script string

//go:embed reality.sh
var realityScript string

//go:embed mirage.sh
var mirageScript string

//go:embed protocols.sh
var protocolsScript string

type Action string

const (
	InstallHTTPS Action = "https-on"
	StartHTTPS   Action = "https-start"
	StopHTTPS    Action = "https-off"
	ExportHTTPS  Action = "https-profile"
	HTTPSStatus  Action = "https-status"
	PurgeHTTPS   Action = "https-purge"
	Status       Action = "status"

	InstallSOCKS Action = "install-socks"
	StopSOCKS    Action = "stop-socks"
	PurgeSOCKS   Action = "socks-purge"

	InstallTCP Action = "reality-on"
	StopTCP    Action = "reality-off"
	ExportTCP  Action = "reality-profile"
	TCPStatus  Action = "reality-status"
	PurgeTCP   Action = "reality-purge"

	InstallMirage Action = "mirage-on"
	StopMirage    Action = "mirage-off"
	ExportMirage  Action = "mirage-profile"
	MirageStatus  Action = "mirage-status"
	PurgeMirage   Action = "mirage-purge"

	InstallHy2 Action = "hy2-on"
	StopHy2    Action = "hy2-off"
	ExportHy2  Action = "hy2-profile"
	Hy2Status  Action = "hy2-status"
	PurgeHy2   Action = "hy2-purge"

	InstallGRPC Action = "grpc-on"
	StopGRPC    Action = "grpc-off"
	ExportGRPC  Action = "grpc-profile"
	GRPCStatus  Action = "grpc-status"
	PurgeGRPC   Action = "grpc-purge"

	InstallSS2022 Action = "ss2022-on"
	StopSS2022    Action = "ss2022-off"
	ExportSS2022  Action = "ss2022-profile"
	SS2022Status  Action = "ss2022-status"
	PurgeSS2022   Action = "ss2022-purge"

	InstallPublicSOCKS Action = "socks-pub-on"
	StopPublicSOCKS    Action = "socks-pub-off"
	ExportPublicSOCKS  Action = "socks-pub-profile"
	PublicSOCKSStatus  Action = "socks-pub-status"
	PurgePublicSOCKS   Action = "socks-pub-purge"

	FleetStatus Action = "fleet-status"
	PurgeAll    Action = "purge-all"
)

type Server struct {
	Host, User, Password, KeyPath, Fingerprint, ClientID string
	Port                                                 int
}

type Result struct {
	Status, SOCKSURL, NodeURL           string
	PublicSOCKSURL, TelegramURL         string
	SOCKSUser, SOCKSPass                string
	SOCKSPort                           int
	Fleet                               map[string]string
}

var (
	username      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	hostname      = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	clientID      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	passwordToken = regexp.MustCompile(`^[0-9a-f]{48}$`)
)

func NewClientID() (string, error) {
	var b [16]byte
	_, err := rand.Read(b[:])
	return hex.EncodeToString(b[:]), err
}

func (s Server) endpoint() (string, error) {
	host := s.Host
	if len(host) == 0 || len(host) > 253 || (net.ParseIP(host) == nil && !hostname.MatchString(host)) {
		return "", errors.New("введите IP или имя сервера без порта и схемы")
	}
	port := s.Port
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return "", errors.New("неверный порт SSH")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// dial also interrupts an in-flight SSH handshake or command on cancellation.
func dial(ctx context.Context, s Server, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	addr, err := s.endpoint()
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{Timeout: 12 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	cc, ch, req, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		stop()
		conn.Close()
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	return ssh.NewClient(cc, ch, req), nil
}

// ProbeFingerprint deliberately ends before authentication. The user compares
// this value with the fingerprint from their VPS console on first use.
func ProbeFingerprint(ctx context.Context, s Server) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var fp string
	stop := errors.New("fingerprint received")
	_, err := dial(ctx, s, &ssh.ClientConfig{User: "sorryrkn-probe", HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp = ssh.FingerprintSHA256(key)
		return stop
	}})
	if fp != "" && errors.Is(err, stop) {
		return fp, nil
	}
	return "", err
}

func methods(s Server) ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod
	if s.KeyPath != "" {
		file, err := os.Open(s.KeyPath)
		if err != nil {
			return nil, errors.New("не удалось открыть SSH-ключ")
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, 256*1024+1))
		if err != nil || len(data) > 256*1024 {
			return nil, errors.New("не удалось прочитать SSH-ключ")
		}
		defer clear(data)
		signer, err := ssh.ParsePrivateKey(data)
		if _, locked := err.(*ssh.PassphraseMissingError); locked && s.Password != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(s.Password))
		}
		if err != nil {
			return nil, errors.New("не удалось открыть SSH-ключ. Проверьте формат и пароль ключа")
		}
		// A passphrase entered for a key must never be sent as an SSH password.
		auth = append(auth, ssh.PublicKeys(signer))
	} else if s.Password != "" {
		auth = append(auth, ssh.Password(s.Password))
	}
	if len(auth) == 0 {
		return nil, errors.New("введите пароль SSH или путь к закрытому ключу")
	}
	return auth, nil
}

type limitedBuffer struct{ data bytes.Buffer }

func (b *limitedBuffer) String() string { return b.data.String() }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	count := len(p)
	if left := 32*1024 - b.data.Len(); left > 0 {
		b.data.Write(p[:min(left, count)])
	}
	return count, nil
}

func verifiedSSH(ctx context.Context, s Server) (*ssh.Client, error) {
	if !username.MatchString(s.User) {
		return nil, errors.New("неверное имя пользователя SSH")
	}
	fp, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(s.Fingerprint, "SHA256:"))
	if !strings.HasPrefix(s.Fingerprint, "SHA256:") || err != nil || len(fp) != 32 {
		return nil, errors.New("сначала подтвердите отпечаток SSH сервера")
	}
	auth, err := methods(s)
	if err != nil {
		return nil, err
	}
	return dial(ctx, s, &ssh.ClientConfig{User: s.User, Auth: auth, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != s.Fingerprint {
			return errors.New("отпечаток SSH сервера изменился. Проверьте ключ через консоль VPS")
		}
		return nil
	}})
}

func Run(ctx context.Context, s Server, action Action) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	switch action {
	case InstallHTTPS, ExportHTTPS, InstallTCP, ExportTCP,
		InstallMirage, ExportMirage, InstallHy2, ExportHy2,
		InstallGRPC, ExportGRPC, InstallSS2022, ExportSS2022,
		InstallPublicSOCKS, ExportPublicSOCKS:
		if !clientID.MatchString(s.ClientID) {
			return Result{}, errors.New("не задан идентификатор VPN-клиента")
		}
	case StartHTTPS, StopHTTPS, HTTPSStatus, PurgeHTTPS, Status,
		InstallSOCKS, StopSOCKS, PurgeSOCKS,
		StopTCP, TCPStatus, PurgeTCP,
		StopMirage, MirageStatus, PurgeMirage,
		StopHy2, Hy2Status, PurgeHy2,
		StopGRPC, GRPCStatus, PurgeGRPC,
		StopSS2022, SS2022Status, PurgeSS2022,
		StopPublicSOCKS, PublicSOCKSStatus, PurgePublicSOCKS,
		FleetStatus, PurgeAll:
		if !clientID.MatchString(s.ClientID) {
			s.ClientID = strings.Repeat("0", 32)
		}
	default:
		return Result{}, errors.New("неизвестная операция сервера")
	}
	client, err := verifiedSSH(ctx, s)
	if err != nil {
		return Result{}, err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return Result{}, err
	}
	defer session.Close()
	var stdout, stderr limitedBuffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	program := scriptForAction(action)
	session.Stdin = strings.NewReader(strings.ReplaceAll(program, "\r\n", "\n"))
	prefix := "exec "
	if s.User != "root" {
		prefix += "sudo -n "
	}
	if err = session.Run(prefix + "sh -s -- " + string(action) + " " + s.ClientID + " " + s.Host); err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		for _, line := range strings.Split(stderr.String(), "\n") {
			if msg, ok := strings.CutPrefix(line, "SRKN_ERROR: "); ok {
				return Result{}, errors.New(msg)
			}
		}
		if strings.Contains(stderr.String(), "sudo:") {
			return Result{}, errors.New("SSH-пользователь должен иметь sudo без запроса пароля. Можно войти под root")
		}
		return Result{}, fmt.Errorf("сервер не завершил операцию. Нужны Debian/Ubuntu с systemd, root или sudo без запроса пароля и доступ к репозиториям пакетов (%v)", err)
	}
	return parseResult(s.Host, action, stdout.String())
}

func scriptForAction(action Action) string {
	a := string(action)
	switch {
	case strings.HasPrefix(a, "reality-"):
		return realityScript
	case strings.HasPrefix(a, "mirage-"):
		return mirageScript
	case strings.HasPrefix(a, "hy2-"), strings.HasPrefix(a, "grpc-"),
		strings.HasPrefix(a, "ss2022-"), strings.HasPrefix(a, "socks-pub-"),
		action == FleetStatus, action == PurgeAll:
		return protocolsScript
	default:
		return script
	}
}

func parseResult(host string, action Action, out string) (Result, error) {
	bad := errors.New("неверный ответ службы SorryRKN")
	fields := strings.Split(strings.TrimSpace(out), "\t")
	if len(fields) < 2 || fields[0] != "SRKN1" {
		return Result{}, bad
	}
	switch action {
	case InstallHTTPS, ExportHTTPS:
		if len(fields) != 3 || fields[1] != "HTTPS" {
			return Result{}, bad
		}
		u, err := url.Parse(fields[2])
		if err != nil || u.Scheme != "naive+https" || u.Host != "sorryrkn.invalid:443" || u.User == nil || !regexp.MustCompile(`^u[0-9a-f]{32}$`).MatchString(u.User.Username()) {
			return Result{}, bad
		}
		if pw, ok := u.User.Password(); !ok || !passwordToken.MatchString(pw) {
			return Result{}, bad
		}
		q := u.Query()
		if net.ParseIP(q.Get("sni")) == nil && !hostname.MatchString(q.Get("sni")) {
			return Result{}, bad
		}
		if raw := q.Get("ca"); raw != "" {
			der, e := base64.RawURLEncoding.DecodeString(raw)
			if e != nil {
				return Result{}, bad
			}
			cert, e := x509.ParseCertificate(der)
			if e != nil || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
				return Result{}, bad
			}
		}
		u.Host = net.JoinHostPort(host, "443")
		status := "Профиль NaïveProxy готов · только TCP"
		if q.Get("relay") != "" {
			if !regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(q.Get("relay")) {
				return Result{}, bad
			}
			status = "Профиль HTTPS готов · TCP и UDP"
		}
		return Result{Status: status, NodeURL: u.String()}, nil
	case InstallSOCKS:
		if len(fields) != 6 || fields[1] != "SOCKS" || fields[2] != "127.0.0.1" || fields[3] != "11080" || fields[4] != "sorryrkn" || !passwordToken.MatchString(fields[5]) {
			return Result{}, bad
		}
		u := url.URL{Scheme: "socks5", User: url.UserPassword(fields[4], fields[5]), Host: net.JoinHostPort(fields[2], fields[3])}
		return Result{Status: "SOCKS5 готов для подключения через SSH", SOCKSURL: u.String()}, nil
	case InstallTCP, ExportTCP:
		if len(fields) != 3 || fields[1] != "REALITY" {
			return Result{}, bad
		}
		u, err := url.Parse(fields[2])
		if err != nil || u.Scheme != "vless" || u.Hostname() != "sorryrkn.invalid" || u.User == nil {
			return Result{}, bad
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port != 8443 {
			return Result{}, bad
		}
		query := u.Query()
		if query.Get("security") != "reality" || query.Get("type") != "tcp" || query.Get("pbk") == "" || query.Get("sni") == "" {
			return Result{}, bad
		}
		u.Host = net.JoinHostPort(host, u.Port())
		return Result{Status: "Профиль VLESS REALITY готов", NodeURL: u.String()}, nil
	case StopTCP, TCPStatus, PurgeTCP,
		StopMirage, MirageStatus, PurgeMirage,
		StopHy2, Hy2Status, PurgeHy2,
		StopGRPC, GRPCStatus, PurgeGRPC,
		StopSS2022, SS2022Status, PurgeSS2022,
		StopPublicSOCKS, PublicSOCKSStatus, PurgePublicSOCKS:
		expectedKind, svcTitle := statusSpecFor(action)
		if len(fields) != 3 || fields[1] != expectedKind {
			return Result{}, bad
		}
		label := map[string]string{"running": "работает", "stopped": "остановлен", "missing": "не установлен"}[fields[2]]
		if label == "" {
			return Result{}, bad
		}
		return Result{Status: svcTitle + ": " + label}, nil
	case InstallMirage, ExportMirage:
		if len(fields) != 3 || fields[1] != "MIRAGE" {
			return Result{}, bad
		}
		u, err := url.Parse(fields[2])
		if err != nil || u.Scheme != "mirage" || u.Hostname() != "sorryrkn.invalid" || u.Port() != "2096" || u.User == nil {
			return Result{}, bad
		}
		if u.Query().Get("pin") == "" {
			return Result{}, bad
		}
		u.Host = net.JoinHostPort(host, "2096")
		return Result{Status: "Профиль SRKN-Mirage v1 («Мираж») готов", NodeURL: u.String()}, nil
	case InstallHy2, ExportHy2:
		if len(fields) != 3 || fields[1] != "HY2" {
			return Result{}, bad
		}
		u, err := url.Parse(fields[2])
		if err != nil || u.Scheme != "hy2" || u.Hostname() != "sorryrkn.invalid" || u.Port() != "8443" || u.User == nil {
			return Result{}, bad
		}
		if u.Query().Get("spki") == "" {
			return Result{}, bad
		}
		u.Host = net.JoinHostPort(host, "8443")
		return Result{Status: "Профиль Hysteria2 + Salamander готов", NodeURL: u.String()}, nil
	case InstallGRPC, ExportGRPC:
		if len(fields) != 3 || fields[1] != "GRPC" {
			return Result{}, bad
		}
		u, err := url.Parse(fields[2])
		if err != nil || u.Scheme != "vless" || u.Hostname() != "sorryrkn.invalid" || u.Port() != "2053" || u.User == nil {
			return Result{}, bad
		}
		if q := u.Query(); q.Get("type") != "grpc" || q.Get("security") != "reality" || q.Get("pbk") == "" || q.Get("sni") == "" {
			return Result{}, bad
		}
		u.Host = net.JoinHostPort(host, "2053")
		return Result{Status: "Профиль VLESS REALITY gRPC готов", NodeURL: u.String()}, nil
	case InstallSS2022, ExportSS2022:
		if len(fields) != 3 || fields[1] != "SS2022" {
			return Result{}, bad
		}
		u, err := url.Parse(fields[2])
		if err != nil || u.Scheme != "ss" || u.Hostname() != "sorryrkn.invalid" || u.Port() != "2083" || u.User == nil {
			return Result{}, bad
		}
		u.Host = net.JoinHostPort(host, "2083")
		return Result{Status: "Профиль Shadowsocks 2022 готов", NodeURL: u.String()}, nil
	case InstallPublicSOCKS, ExportPublicSOCKS:
		if len(fields) != 5 || fields[1] != "SOCKS-PUB" {
			return Result{}, bad
		}
		port, err := strconv.Atoi(fields[2])
		if err != nil || port != 10808 || !username.MatchString(fields[3]) || fields[4] == "" || strings.ContainsAny(fields[4], " \t\r\n") {
			return Result{}, bad
		}
		u := url.URL{Scheme: "socks5", User: url.UserPassword(fields[3], fields[4]), Host: net.JoinHostPort(host, fields[2])}
		tg := "tg://socks?" + (url.Values{"server": {host}, "port": {fields[2]}, "user": {fields[3]}, "pass": {fields[4]}}).Encode()
		return Result{
			Status:         fmt.Sprintf("Публичный SOCKS5 (%s:10808) активен", host),
			PublicSOCKSURL: u.String(),
			TelegramURL:    tg,
			SOCKSUser:      fields[3],
			SOCKSPass:      fields[4],
			SOCKSPort:      port,
		}, nil
	case FleetStatus:
		if len(fields) < 3 || fields[1] != "FLEET" {
			return Result{}, bad
		}
		fleet := make(map[string]string, len(fields)-2)
		labels := map[string]string{"running": "работает", "stopped": "остановлен", "missing": "не установлен"}
		var parts []string
		for _, item := range fields[2:] {
			k, v, ok := strings.Cut(item, ":")
			if !ok || labels[v] == "" {
				return Result{}, bad
			}
			fleet[k] = v
			parts = append(parts, fmt.Sprintf("%s=%s", k, labels[v]))
		}
		return Result{Status: strings.Join(parts, " · "), Fleet: fleet}, nil
	case PurgeAll:
		if len(fields) != 3 || fields[1] != "PURGED" || fields[2] != "all" {
			return Result{}, bad
		}
		return Result{Status: "Все компоненты и правила SorryRKN удалены с сервера"}, nil
	default:
		if len(fields) != 4 || fields[1] != "STATUS" {
			return Result{}, bad
		}
		labels := map[string]string{"running": "работает", "stopped": "остановлен", "missing": "не установлен"}
		v, vok := strings.CutPrefix(fields[2], "vpn:")
		p, pok := strings.CutPrefix(fields[3], "socks:")
		if !vok || !pok || labels[v] == "" || labels[p] == "" {
			return Result{}, bad
		}
		return Result{Status: "VPN: " + labels[v] + " · SOCKS5: " + labels[p]}, nil
	}
}

func statusSpecFor(action Action) (kind, title string) {
	switch action {
	case StopTCP, TCPStatus, PurgeTCP:
		return "REALITY-STATUS", "VLESS REALITY"
	case StopMirage, MirageStatus, PurgeMirage:
		return "MIRAGE-STATUS", "SRKN-Mirage v1"
	case StopHy2, Hy2Status, PurgeHy2:
		return "HY2-STATUS", "Hysteria2"
	case StopGRPC, GRPCStatus, PurgeGRPC:
		return "GRPC-STATUS", "VLESS gRPC"
	case StopSS2022, SS2022Status, PurgeSS2022:
		return "SS2022-STATUS", "Shadowsocks 2022"
	case StopPublicSOCKS, PublicSOCKSStatus, PurgePublicSOCKS:
		return "SOCKS-PUB-STATUS", "Публичный SOCKS5"
	default:
		return "", ""
	}
}
