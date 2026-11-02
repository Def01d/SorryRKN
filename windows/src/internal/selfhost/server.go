// Package selfhost provisions the server selected by the user over pinned SSH.
package selfhost

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
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

type Action string

const (
	InstallVPN   Action = "install-vpn"
	StartVPN     Action = "start-vpn"
	StopVPN      Action = "stop-vpn"
	ExportVPN    Action = "export-vpn"
	Status       Action = "status"
	InstallSOCKS Action = "install-socks"
	StopSOCKS    Action = "stop-socks"
)

type Server struct {
	Host, User, Password, KeyPath, Fingerprint, ClientID string
	Port                                                 int
}

type Result struct {
	Status, VPNConfig, SOCKSURL string
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

func Run(ctx context.Context, s Server, action Action) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	switch action {
	case InstallVPN, ExportVPN:
		if !clientID.MatchString(s.ClientID) {
			return Result{}, errors.New("не задан идентификатор VPN-клиента")
		}
	case StartVPN, StopVPN, Status, InstallSOCKS, StopSOCKS:
		s.ClientID = strings.Repeat("0", 32)
	default:
		return Result{}, errors.New("неизвестная операция сервера")
	}
	if !username.MatchString(s.User) {
		return Result{}, errors.New("неверное имя пользователя SSH")
	}
	fp, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(s.Fingerprint, "SHA256:"))
	if !strings.HasPrefix(s.Fingerprint, "SHA256:") || err != nil || len(fp) != 32 {
		return Result{}, errors.New("сначала подтвердите отпечаток SSH сервера")
	}
	auth, err := methods(s)
	if err != nil {
		return Result{}, err
	}
	client, err := dial(ctx, s, &ssh.ClientConfig{User: s.User, Auth: auth, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != s.Fingerprint {
			return errors.New("отпечаток SSH сервера изменился. Проверьте ключ через консоль VPS")
		}
		return nil
	}})
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
	session.Stdin = strings.NewReader(strings.ReplaceAll(script, "\r\n", "\n"))
	prefix := "exec "
	if s.User != "root" {
		prefix += "sudo -n "
	}
	if err = session.Run(prefix + "sh -s -- " + string(action) + " " + s.ClientID); err != nil {
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

func privateIPv4(value string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.Is4() && ip.IsPrivate()
}
func wgKey(value string) bool {
	b, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == value
}
func parseResult(host string, action Action, out string) (Result, error) {
	bad := errors.New("неверный ответ службы SorryRKN")
	fields := strings.Split(strings.TrimSpace(out), "\t")
	if len(fields) < 2 || fields[0] != "SRKN1" {
		return Result{}, bad
	}
	switch action {
	case InstallVPN, ExportVPN:
		if len(fields) != 7 || fields[1] != "VPN" || !wgKey(fields[2]) || !wgKey(fields[3]) || !wgKey(fields[4]) || !privateIPv4(fields[5]) || fields[6] != "51823" {
			return Result{}, bad
		}
		config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n", fields[2], fields[5], fields[3], fields[4], net.JoinHostPort(host, fields[6]))
		return Result{Status: "Профиль WireGuard готов", VPNConfig: config}, nil
	case InstallSOCKS:
		if len(fields) != 6 || fields[1] != "SOCKS" || !privateIPv4(fields[2]) || fields[3] != "11080" || fields[4] != "sorryrkn" || !passwordToken.MatchString(fields[5]) {
			return Result{}, bad
		}
		u := url.URL{Scheme: "socks5", User: url.UserPassword(fields[4], fields[5]), Host: net.JoinHostPort(fields[2], fields[3])}
		return Result{Status: "SOCKS5 доступен внутри VPN", SOCKSURL: u.String()}, nil
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
