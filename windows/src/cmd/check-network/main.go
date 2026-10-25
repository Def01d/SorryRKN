// check-network makes anonymous application-level probes. It changes no network
// settings, does not start WinDivert, and requires no administrator privileges.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sorryrkn/internal/core"
	"sync"
	"time"
)

func main() {
	output := flag.String("output", "", "optional JSON report path")
	matrix := flag.Bool("dns-matrix", false, "compare all bundled DNS profiles against eight public AI services")
	profile := flag.String("dns-profile", "comss", "DNS profile for the ordinary network diagnostic")
	verifyData := flag.String("verify-data", "", "verify a signed local JSON envelope without network or driver")
	flag.Parse()
	if *verifyData != "" {
		b, err := os.ReadFile(*verifyData)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		payload, err := core.VerifyEnvelope(b)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		report := map[string]any{"signature_verified": true, "scope": "offline_signature_and_expiry_only", "payload": json.RawMessage(payload)}
		encoded, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(encoded))
		if *output != "" {
			if err = core.SaveJSON(*output, report); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		return
	}
	if *matrix {
		ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
		defer cancel()
		report := core.ScanDNSProfiles(ctx, core.LoadDNSCatalog(""))
		b, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(b))
		if *output != "" {
			if err := core.SaveJSON(*output, report); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resolver := core.NewSmartDNS(core.DomainRules{Builtin: true, Secure: true, DNSProfile: *profile})
	defer resolver.Close()
	var direct, repaired core.Check
	var directExtras, repairedExtras []core.Target
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); direct = core.Probe(ctx, "system DNS") }()
	go func() { defer wg.Done(); repaired = core.ProbeWithDNS(ctx, "protected DNS", resolver) }()
	go func() { defer wg.Done(); directExtras = core.ProbeExtras(ctx) }()
	go func() { defer wg.Done(); repairedExtras = core.ProbeExtrasWithDNS(ctx, resolver) }()
	wg.Wait()
	report := map[string]any{"version": core.Version, "checked_at": time.Now().UTC().Format(time.RFC3339), "direct": direct, "protected_dns": repaired, "direct_extras": directExtras, "comss_extras": repairedExtras, "scope": "Anonymous HTTPS/API/WebSocket checks only; playback, calls and signed-in account actions are not tested. No DPI driver was started."}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
	if *output != "" {
		if err = core.SaveJSON(*output, report); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
