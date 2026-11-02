package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

// Capture the actual Cronet ClientHello when the VPS has only an IP address.
func TestNaiveIPClientHelloOmitsSNI(t *testing.T) {
	root := runtimeDir(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	sni := make(chan string, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(4 * time.Second))
		tls.Server(c, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni <- hello.ServerName
			cancel()
			return nil, errors.New("fixture captured hello")
		}}).Handshake()
	}()
	link := fmt.Sprintf("naive+https://fixture:test@%s/?sni=127.0.0.1", listener.Addr())
	p, _, err := parseNode(link)
	if err != nil {
		t.Fatal(err)
	}
	_, err = probeHTTPS(ctx, root, p, "https://example.org/", nil)
	if err == nil {
		t.Fatal("unauthenticated fixture unexpectedly accepted")
	}
	select {
	case name := <-sni:
		if name != "" {
			t.Fatal("client sent SNI for literal IP")
		}
	default:
		t.Fatal("Cronet ClientHello was not captured")
	}
}

func naiveFixture(t *testing.T, port int) (object, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SorryRKN fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "connect.sorry.test"}, DNSNames: []string{"connect.sorry.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	sum := sha256.Sum256(ca.RawSubjectPublicKeyInfo)
	params := url.Values{"sni": {"connect.sorry.test"}, "ca": {base64.RawURLEncoding.EncodeToString(der)}, "spki": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	inbound := object{"type": "naive", "network": "tcp", "listen": "127.0.0.1", "listen_port": port, "users": []object{{"username": "fixture", "password": "test-pass"}}, "tls": object{"enabled": true, "certificate": cert, "key": key}}
	return inbound, fmt.Sprintf("naive+https://fixture:test-pass@127.0.0.1:%d/?%s", port, params.Encode())
}
