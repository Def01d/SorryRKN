//go:build !clientonly

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"sorryrkn/internal/mirage"
)

func runServerCmd(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	listen := fs.String("listen", ":443", "TLS listen address")
	certFile := fs.String("cert", "", "path to TLS certificate PEM")
	keyFile := fs.String("key", "", "path to TLS private key PEM")
	secretFile := fs.String("secret-file", "", "path to 32-byte PSK file (base64url/hex)")
	secretVal := fs.String("secret", os.Getenv("MIRAGE_SECRET"), "PSK (base64url/hex)")
	chaff := fs.Bool("chaff", true, "enable obfuscation chaff padding")
	if err := fs.Parse(args); err != nil {
		return err
	}

	secStr := strings.TrimSpace(*secretVal)
	if *secretFile != "" {
		raw, err := os.ReadFile(*secretFile)
		if err != nil {
			return err
		}
		secStr = strings.TrimSpace(string(raw))
	}
	if secStr == "" {
		return errors.New("не указан секретный ключ (--secret-file)")
	}
	secret, err := mirage.DecodeSecret(secStr)
	if err != nil {
		return err
	}

	srv, err := mirage.NewServer(mirage.ServerConfig{
		ListenAddr:          *listen,
		Secret:              secret,
		CertFile:            *certFile,
		KeyFile:             *keyFile,
		Chaff:               *chaff,
		AllowPrivateTargets: false,
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Serve(ctx)
}

func runKeygenCmd(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	cn := fs.String("cn", "edge-telemetry.local", "certificate CommonName / SNI hint")
	outDir := fs.String("out-dir", "", "optional directory to write cert.pem, key.pem, secret, pin")
	if err := fs.Parse(args); err != nil {
		return err
	}

	secB64, pinHex, certPEM, keyPEM, err := mirage.GenerateCredentials(*cn)
	if err != nil {
		return err
	}

	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*outDir, "cert.pem"), certPEM, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*outDir, "key.pem"), keyPEM, 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*outDir, "secret"), []byte(secB64+"\n"), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*outDir, "pin"), []byte(pinHex+"\n"), 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("SECRET=%s\nPIN=%s\n", secB64, pinHex)
	return nil
}
