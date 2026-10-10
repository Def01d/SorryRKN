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
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resolver := core.NewSmartDNS(core.DomainRules{Builtin: true, Secure: true})
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
