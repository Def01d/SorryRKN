package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"sorryrkn/internal/mirage"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := strings.ToLower(strings.TrimSpace(os.Args[1]))
	switch sub {
	case "client":
		if err := runClient(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "mirage client error: %v\n", err)
			os.Exit(1)
		}
	case "server":
		if err := runServerCmd(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "mirage server error: %v\n", err)
			os.Exit(1)
		}
	case "keygen":
		if err := runKeygenCmd(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "mirage keygen error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("sorryrkn-mirage v%d\n", mirage.ProtocolVersion)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sorryrkn-mirage <client|server|keygen|version> [flags]")
}

type clientFileConfig struct {
	URI       string `json:"uri"`
	Listen    string `json:"listen"`
	SocksUser string `json:"socks_user"`
	SocksPass string `json:"socks_pass"`
	Chaff     *bool  `json:"chaff,omitempty"`
}

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	uriFlag := fs.String("uri", os.Getenv("MIRAGE_URI"), "mirage:// share URI")
	cfgFile := fs.String("config", "", "path to JSON client config")
	listenFlag := fs.String("listen", "127.0.0.1:10818", "local SOCKS5 listen address")
	userFlag := fs.String("socks-user", os.Getenv("MIRAGE_SOCKS_USER"), "local SOCKS5 username")
	passFlag := fs.String("socks-pass", os.Getenv("MIRAGE_SOCKS_PASS"), "local SOCKS5 password")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rawURI := strings.TrimSpace(*uriFlag)
	listen := strings.TrimSpace(*listenFlag)
	user := *userFlag
	pass := *passFlag
	var chaffOverride *bool

	if *cfgFile != "" {
		raw, err := os.ReadFile(*cfgFile)
		if err != nil {
			return err
		}
		var fc clientFileConfig
		if err := json.Unmarshal(raw, &fc); err != nil {
			return err
		}
		if fc.URI != "" {
			rawURI = fc.URI
		}
		if fc.Listen != "" {
			listen = fc.Listen
		}
		if fc.SocksUser != "" {
			user = fc.SocksUser
		}
		if fc.SocksPass != "" {
			pass = fc.SocksPass
		}
		chaffOverride = fc.Chaff
	}

	cfg, err := mirage.ParseURI(rawURI)
	if err != nil {
		return err
	}
	cfg.ListenAddr = listen
	cfg.AuthUser = user
	cfg.AuthPass = pass
	if chaffOverride != nil {
		cfg.Chaff = *chaffOverride
	}

	cli, err := mirage.NewClient(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return cli.Serve(ctx)
}
