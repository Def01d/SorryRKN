// Package mirage implements SRKN-Mirage v1, an authenticated TLS 1.3
// covert-knock VPN transport with uTLS Chrome fingerprints, active-probe
// HTTP HTML camouflage, dual-AEAD encrypted framing, polymorphic initial
// padding, chaff injection, and automatic carrier rotation.
package mirage

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// ProtocolVersion identifies the SRKN-Mirage wire specification.
	ProtocolVersion = 1

	// SecretSize is the length in bytes of the pre-shared master secret.
	SecretSize = 32

	// MaxClockSkew bounds client/server timestamp difference during knocks.
	MaxClockSkew = 90 * time.Second

	// MaxFrameBody is the maximum decrypted payload size in a single frame.
	MaxFrameBody = 16 * 1024

	// StreamChunkSize is the maximum application payload inside one FrameData.
	StreamChunkSize = 14 * 1024

	// InitialStreamWindow is the per-stream receive credit in bytes.
	InitialStreamWindow = 1024 * 1024

	// StreamCreditThreshold triggers sending a FrameCredit replenishment.
	StreamCreditThreshold = 256 * 1024

	// DefaultMTU is exposed for client metadata consistency.
	DefaultMTU = 1360
)

// Frame types on the encrypted carrier stream.
const (
	FrameOpenTCP byte = 0x01
	FrameOpenOK  byte = 0x02
	FrameData    byte = 0x03
	FrameClose   byte = 0x04
	FrameUDP     byte = 0x05
	FrameChaff   byte = 0x06
	FrameRetire  byte = 0x07
	FrameCredit  byte = 0x08
	FrameFIN     byte = 0x09
)

// Address types matching SOCKS5 / wire encoding.
const (
	AddrIPv4   byte = 0x01
	AddrDomain byte = 0x03
	AddrIPv6   byte = 0x04
)

// ClientConfig holds all parameters parsed from a mirage:// URI or flags.
type ClientConfig struct {
	Name        string
	ServerHost  string
	ServerPort  uint16
	SNI         string
	CoverHost   string
	PinSHA256   [32]byte
	PinHex      string
	Secret      [SecretSize]byte
	Fingerprint string
	Chaff       bool
	MTU         int
	ListenAddr  string
	AuthUser    string
	AuthPass    string
	DoHURLs     []string
}

// ParseURI parses a mirage:// share link into a validated ClientConfig.
//
// Format:
//
//	mirage://<b64url-secret>@<host>:<port>?sni=<sni>&pin=<sha256>&cover=<host>&fp=chrome&chaff=1&mtu=1360#Name
func ParseURI(raw string) (*ClientConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("пустая ссылка mirage://")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("некорректная ссылка mirage://: %w", err)
	}
	if strings.ToLower(u.Scheme) != "mirage" {
		return nil, fmt.Errorf("неподдерживаемая схема %q", u.Scheme)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("в ссылке mirage:// отсутствует секретный ключ")
	}
	secret, err := DecodeSecret(u.User.Username())
	if err != nil {
		return nil, fmt.Errorf("неверный секрет mirage://: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("в ссылке mirage:// отсутствует адрес сервера")
	}
	port := uint16(443)
	if ps := u.Port(); ps != "" {
		n, err := strconv.Atoi(ps)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("неверный порт %q", ps)
		}
		port = uint16(n)
	}
	q := u.Query()
	pinStr := q.Get("pin")
	if pinStr == "" {
		pinStr = q.Get("sha256")
	}
	pin, pinHex, err := DecodePin(pinStr)
	if err != nil {
		return nil, fmt.Errorf("неверный TLS pin mirage://: %w", err)
	}
	sni := strings.TrimSpace(q.Get("sni"))
	if sni == "" && net.ParseIP(host) == nil {
		sni = host
	}
	cover := strings.TrimSpace(q.Get("cover"))
	if cover == "" {
		if sni != "" {
			cover = sni
		} else {
			cover = host
		}
	}
	fp := strings.ToLower(strings.TrimSpace(q.Get("fp")))
	if fp == "" {
		fp = "chrome"
	}
	chaff := true
	if cv := strings.ToLower(strings.TrimSpace(q.Get("chaff"))); cv == "0" || cv == "false" || cv == "off" {
		chaff = false
	}
	mtu := DefaultMTU
	if ms := strings.TrimSpace(q.Get("mtu")); ms != "" {
		if n, err := strconv.Atoi(ms); err == nil && n >= 576 && n <= 9000 {
			mtu = n
		}
	}
	name := strings.TrimSpace(u.Fragment)
	if name == "" {
		name = "SorryRKN Мираж"
	}
	return &ClientConfig{
		Name:        name,
		ServerHost:  host,
		ServerPort:  port,
		SNI:         sni,
		CoverHost:   cover,
		PinSHA256:   pin,
		PinHex:      pinHex,
		Secret:      secret,
		Fingerprint: fp,
		Chaff:       chaff,
		MTU:         mtu,
	}, nil
}

// URI formats a ClientConfig back into a canonical mirage:// share URL.
func (c *ClientConfig) URI() string {
	u := &url.URL{
		Scheme:   "mirage",
		User:     url.User(base64.RawURLEncoding.EncodeToString(c.Secret[:])),
		Host:     net.JoinHostPort(c.ServerHost, strconv.Itoa(int(c.ServerPort))),
		Fragment: c.Name,
	}
	q := url.Values{}
	if c.SNI != "" {
		q.Set("sni", c.SNI)
	}
	q.Set("pin", c.PinHex)
	if c.CoverHost != "" && c.CoverHost != c.SNI {
		q.Set("cover", c.CoverHost)
	}
	if c.Fingerprint != "" && c.Fingerprint != "chrome" {
		q.Set("fp", c.Fingerprint)
	}
	if !c.Chaff {
		q.Set("chaff", "0")
	}
	if c.MTU > 0 && c.MTU != DefaultMTU {
		q.Set("mtu", strconv.Itoa(c.MTU))
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// DecodeSecret parses a 32-byte PSK encoded as base64url, standard base64, or hex.
func DecodeSecret(s string) ([SecretSize]byte, error) {
	var out [SecretSize]byte
	s = strings.TrimSpace(s)
	decoders := []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
		hex.DecodeString,
	}
	for _, fn := range decoders {
		b, err := fn(s)
		if err == nil && len(b) == SecretSize {
			copy(out[:], b)
			return out, nil
		}
	}
	return out, errors.New("ожидался 32-байтовый ключ")
}

// DecodePin normalizes and validates a SHA-256 certificate pin (hex or base64).
func DecodePin(s string) ([32]byte, string, error) {
	var pin [32]byte
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.TrimPrefix(s, "sha256/")
	cleanHex := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s, ":", ""), " ", ""))
	if len(cleanHex) == 64 {
		b, err := hex.DecodeString(cleanHex)
		if err == nil && len(b) == 32 {
			copy(pin[:], b)
			return pin, cleanHex, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		copy(pin[:], b)
		return pin, hex.EncodeToString(b), nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil && len(b) == 32 {
		copy(pin[:], b)
		return pin, hex.EncodeToString(b), nil
	}
	return pin, "", errors.New("требуется SHA-256 отпечаток сертификата (64 hex-символа)")
}

// knockPayloadLen = ephPub(32) + ts(8) + nonce(16) + mac(16) = 72 bytes.
const knockPayloadLen = 32 + 8 + 16 + 16

// serverAckLen = ephPub(32) + nonce(16) + mac(16) = 64 bytes.
const serverAckLen = 32 + 16 + 16

type knockData struct {
	ClientEphPub [32]byte
	Timestamp    int64
	ClientNonce  [16]byte
	ReplayID     string
}

func deriveSubkey(psk [SecretSize]byte, label string) []byte {
	r := hkdf.New(sha256.New, psk[:], nil, []byte(label))
	k := make([]byte, 32)
	_, _ = io.ReadFull(r, k)
	return k
}

func buildKnockToken(psk [SecretSize]byte, ephPub [32]byte, now time.Time) (string, [16]byte, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", nonce, err
	}
	buf := make([]byte, knockPayloadLen)
	copy(buf[0:32], ephPub[:])
	binary.BigEndian.PutUint64(buf[32:40], uint64(now.Unix()))
	copy(buf[40:56], nonce[:])

	macKey := deriveSubkey(psk, "srkn-mirage-knock-v1")
	m := hmac.New(sha256.New, macKey)
	m.Write(buf[:56])
	copy(buf[56:72], m.Sum(nil)[:16])

	return base64.RawURLEncoding.EncodeToString(buf), nonce, nil
}

func verifyKnockToken(psk [SecretSize]byte, token string, now time.Time) (knockData, bool) {
	var kd knockData
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil || len(raw) != knockPayloadLen {
		return kd, false
	}
	macKey := deriveSubkey(psk, "srkn-mirage-knock-v1")
	m := hmac.New(sha256.New, macKey)
	m.Write(raw[:56])
	expected := m.Sum(nil)[:16]
	if !hmac.Equal(raw[56:72], expected) {
		return kd, false
	}
	ts := int64(binary.BigEndian.Uint64(raw[32:40]))
	diff := now.Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if time.Duration(diff)*time.Second > MaxClockSkew {
		return kd, false
	}
	copy(kd.ClientEphPub[:], raw[0:32])
	kd.Timestamp = ts
	copy(kd.ClientNonce[:], raw[40:56])
	// Replay identifier binds timestamp, nonce, and MAC tag.
	kd.ReplayID = hex.EncodeToString(raw[32:72])
	return kd, true
}

func buildServerAck(psk [SecretSize]byte, clientEph [32]byte, clientNonce [16]byte, serverEph [32]byte) (string, [16]byte, error) {
	var srvNonce [16]byte
	if _, err := rand.Read(srvNonce[:]); err != nil {
		return "", srvNonce, err
	}
	buf := make([]byte, serverAckLen)
	copy(buf[0:32], serverEph[:])
	copy(buf[32:48], srvNonce[:])

	ackKey := deriveSubkey(psk, "srkn-mirage-ack-v1")
	m := hmac.New(sha256.New, ackKey)
	m.Write([]byte("srkn-srv-ack"))
	m.Write(clientEph[:])
	m.Write(clientNonce[:])
	m.Write(serverEph[:])
	m.Write(srvNonce[:])
	copy(buf[48:64], m.Sum(nil)[:16])

	return base64.RawURLEncoding.EncodeToString(buf), srvNonce, nil
}

func verifyServerAck(psk [SecretSize]byte, token string, clientEph [32]byte, clientNonce [16]byte) ([32]byte, [16]byte, bool) {
	var srvEph [32]byte
	var srvNonce [16]byte
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil || len(raw) != serverAckLen {
		return srvEph, srvNonce, false
	}
	copy(srvEph[:], raw[0:32])
	copy(srvNonce[:], raw[32:48])

	ackKey := deriveSubkey(psk, "srkn-mirage-ack-v1")
	m := hmac.New(sha256.New, ackKey)
	m.Write([]byte("srkn-srv-ack"))
	m.Write(clientEph[:])
	m.Write(clientNonce[:])
	m.Write(srvEph[:])
	m.Write(srvNonce[:])
	if !hmac.Equal(raw[48:64], m.Sum(nil)[:16]) {
		return srvEph, srvNonce, false
	}
	return srvEph, srvNonce, true
}

type sessionKeys struct {
	C2SHeader [32]byte
	C2SBody   [32]byte
	S2CHeader [32]byte
	S2CBody   [32]byte
}

func deriveSessionKeys(shared []byte, psk [SecretSize]byte, clientNonce, serverNonce [16]byte) sessionKeys {
	ikm := make([]byte, 0, len(shared)+len(psk))
	ikm = append(ikm, shared...)
	ikm = append(ikm, psk[:]...)
	salt := make([]byte, 0, 32)
	salt = append(salt, clientNonce[:]...)
	salt = append(salt, serverNonce[:]...)

	r := hkdf.New(sha256.New, ikm, salt, []byte("srkn-mirage-v1-master"))
	var sk sessionKeys
	_, _ = io.ReadFull(r, sk.C2SHeader[:])
	_, _ = io.ReadFull(r, sk.C2SBody[:])
	_, _ = io.ReadFull(r, sk.S2CHeader[:])
	_, _ = io.ReadFull(r, sk.S2CBody[:])
	return sk
}

// GenerateCredentials creates a random 32-byte PSK and a self-signed ECDSA P-256
// TLS certificate valid for 10 years, returning base64url secret, hex pin, cert PEM, key PEM.
func GenerateCredentials(commonName string) (secretB64 string, pinHex string, certPEM []byte, keyPEM []byte, err error) {
	if strings.TrimSpace(commonName) == "" {
		commonName = "edge-telemetry.local"
	}
	var psk [SecretSize]byte
	if _, err = rand.Read(psk[:]); err != nil {
		return "", "", nil, nil, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", nil, nil, err
	}
	now := time.Now().UTC().Add(-1 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Cloud Edge Services"}},
		NotBefore:    now,
		NotAfter:     now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{commonName},
	}
	if ip := net.ParseIP(commonName); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
		tmpl.DNSNames = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", nil, nil, err
	}
	sum := sha256.Sum256(der)
	secretB64 = base64.RawURLEncoding.EncodeToString(psk[:])
	pinHex = hex.EncodeToString(sum[:])
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return secretB64, pinHex, certPEM, keyPEM, nil
}

// coverHTMLPage is served to unauthenticated HTTP probes or replayed knocks.
const coverHTMLPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Service Gateway</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0f1419;color:#d6dde6;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{max-width:460px;padding:32px;border:1px solid #24303f;border-radius:12px;background:#151c24}
h1{font-size:18px;margin:0 0 10px;color:#fff}
p{font-size:14px;line-height:1.5;margin:0;color:#93a3b5}
</style>
</head>
<body>
<div class="box">
<h1>API Telemetry Endpoint</h1>
<p>This edge gateway accepts authenticated telemetry ingestion requests only. Browser access is not enabled for this host.</p>
</div>
</body>
</html>
`

// makeAEADs initializes header and body ChaCha20-Poly1305 AEAD instances.
func makeAEADs(hdrKey, bodyKey [32]byte) (hdrAEAD, bodyAEAD cipher.AEAD, err error) {
	h, err := chacha20poly1305.New(hdrKey[:])
	if err != nil {
		return nil, nil, err
	}
	b, err := chacha20poly1305.New(bodyKey[:])
	if err != nil {
		return nil, nil, err
	}
	return h, b, nil
}
