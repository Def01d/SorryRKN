package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProfilesBundled(t *testing.T) {
	root := "../../runtime/zapret"
	c, e := LoadCatalog(root)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Profiles) != 22 {
		t.Fatal(len(c.Profiles))
	}
	for _, p := range c.Profiles {
		if _, e = ResolveArgs(p, root, filepath.Join(root, "bin")); e != nil {
			t.Fatalf("%s: %v", p.ID, e)
		}
	}
	if c.Profiles[0].ID != "general" {
		t.Fatal("wrong initial candidate")
	}
}
func TestProfileRejectsCodeAndTraversal(t *testing.T) {
	for _, s := range []string{`--lua-init=evil.lua`, `--hostlist=@LISTS@/../secret.txt`, `--dpi-desync=foo & calc.exe`, `--debug=@BIN@/evil.exe`, `--dpi-desync=fake %UNRESOLVED%`} {
		_, e := ParseBAT("general.bat", `start "x" "%BIN%winws.exe" --wf-tcp=443 --wf-udp=443 `+s)
		if e == nil {
			t.Fatal("accepted", s)
		}
	}
}
func TestBATQuotesAndContinued(t *testing.T) {
	p, e := ParseBAT("general.bat", "prefix\nstart \"x\" \"%BIN%winws.exe\" --wf-tcp=443,%GameFilterTCP% --wf-udp=443 ^\r\n--filter-tcp=443 --hostlist=\"%LISTS%list-general.txt\" --dpi-desync=fake\r\necho SHOULD_NOT_EXECUTE")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(strings.Join(p.Args, " "), "echo") || p.Args[0] != "--wf-tcp=443,12" {
		t.Fatal(p)
	}
}
func query(name string, typ uint16) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[:2], 0xbeef)
	q[2] = 1
	q[5] = 1
	for _, s := range strings.Split(name, ".") {
		q = append(q, byte(len(s)))
		q = append(q, s...)
	}
	q = append(q, 0, byte(typ>>8), byte(typ), 0, 1)
	return q
}
func TestSelectiveDNS(t *testing.T) {
	s := NewSmartDNS()
	for _, host := range []string{"chatgpt.com", "api.anthropic.com", "gemini.google.com"} {
		for _, qt := range []uint16{28, 64, 65} {
			q := query(host, qt)
			r := s.Resolve(context.Background(), q)
			if len(r) != len(q) || !bytes.Equal(r[:2], q[:2]) || r[2]&128 == 0 || r[3]&15 != 0 {
				t.Fatal(host, qt, r)
			}
		}
	}
	for _, host := range []string{"evilchatgpt.com", "chatgpt.com.evil.example", "google.com", "example.com"} {
		if s.Resolve(context.Background(), query(host, 1)) != nil {
			t.Fatal("ordinary DNS intercepted", host)
		}
	}
}
func TestDNSDohIntegrityAndCache(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		q := make([]byte, r.ContentLength)
		r.Body.Read(q)
		w.Write(DNSReply(q, 0))
	}))
	defer server.Close()
	s := NewSmartDNS()
	s.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(server.URL, "http://")
		return http.DefaultTransport.RoundTrip(r)
	})}
	q := query("chatgpt.com", 1)
	r := s.Resolve(context.Background(), q)
	if r[3]&15 != 0 {
		t.Fatal(r)
	}
	q[0] = 7
	r = s.Resolve(context.Background(), q)
	if r[0] != 7 || count.Load() != 1 {
		t.Fatal("cache ID/reuse mismatch")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestDNSPacketIPv4IPv6(t *testing.T) {
	for _, version := range []byte{4, 6} {
		q := query("claude.ai", 28)
		offset := 20
		if version == 6 {
			offset = 40
		}
		packet := make([]byte, offset+8+len(q))
		if version == 4 {
			packet[0] = 0x45
			packet[9] = 17
			copy(packet[12:20], []byte{1, 2, 3, 4, 8, 8, 8, 8})
		} else {
			packet[0] = 0x60
			packet[6] = 17
			packet[8] = 1
			packet[24] = 2
		}
		binary.BigEndian.PutUint16(packet[offset:], 51234)
		binary.BigEndian.PutUint16(packet[offset+2:], 53)
		binary.BigEndian.PutUint16(packet[offset+4:], uint16(len(q)+8))
		copy(packet[offset+8:], q)
		payload, _, ok := DNSPayload(packet)
		if !ok || !bytes.Equal(payload, q) {
			t.Fatal("parse failed")
		}
		r := ReplyPacket(packet, DNSReply(q, 0))
		if binary.BigEndian.Uint16(r[offset:]) != 53 || binary.BigEndian.Uint16(r[offset+2:]) != 51234 {
			t.Fatal("port reversal")
		}
		if version == 4 && !bytes.Equal(r[12:16], packet[16:20]) {
			t.Fatal("IPv4 reversal")
		}
		if version == 6 && !bytes.Equal(r[8:24], packet[24:40]) {
			t.Fatal("IPv6 reversal")
		}
	}
}
func TestMalformedDNS(t *testing.T) {
	for _, b := range [][]byte{nil, make([]byte, 12), query("x.example", 1)[:13], append(query("x.example", 1)[:12], 0xc0, 12)} {
		if _, _, _, e := Question(b); e == nil {
			t.Fatal("malformed accepted")
		}
	}
}
func TestWSFrameLimits(t *testing.T) {
	for _, b := range [][]byte{{0x81, 0x7f, 0, 0, 0, 1, 0, 0, 0, 0}, {0x81, 0x80}, {1, 0}} {
		if _, _, e := ReadWSFrame(bytes.NewReader(b)); e == nil {
			t.Fatal("invalid frame accepted")
		}
	}
	op, p, e := ReadWSFrame(bytes.NewReader([]byte{0x81, 2, 'o', 'k'}))
	if e != nil || op != 1 || string(p) != "ok" {
		t.Fatal(op, p, e)
	}
}
func TestHTTPProbeRejectsFalsePositive(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("provider block page")) }))
	defer s.Close()
	if probeHTTP(context.Background(), s.Client(), s.URL, []byte("gateway.discord.gg")) == nil {
		t.Fatal("block page accepted")
	}
}
func TestReleaseManifest(t *testing.T) {
	valid := Release{Platform: "windows-x64", Code: 10001, Name: "1.0.1", URL: "https://raw.githubusercontent.com/Def01d/SorryRKN/windows-v1.0.1/setup.exe", SHA: strings.Repeat("a", 64), Size: 100}
	if e := valid.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, url := range []string{"http://raw.githubusercontent.com/Def01d/SorryRKN/windows-v1/x.exe", "https://evil.example/setup.exe", "https://raw.githubusercontent.com/evil/SorryRKN/windows-v1/x.exe", "https://user:secret@raw.githubusercontent.com/Def01d/SorryRKN/windows-v1/x.exe"} {
		r := valid
		r.URL = url
		if r.Validate() == nil {
			t.Fatal("accepted", url)
		}
	}
	valid.Size = 129 * 1024 * 1024
	if valid.Validate() == nil {
		t.Fatal("oversized update accepted")
	}
}
func TestConfigAndSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := DefaultConfig()
	c.Method = "manual"
	if e := SaveJSON(path, c); e != nil {
		t.Fatal(e)
	}
	if LoadConfig(path).Method != "manual" {
		t.Fatal("config not persisted")
	}
	s, e := NewSecret()
	if e != nil || !ValidSecret(s) {
		t.Fatal(s, e)
	}
	if _, e = ProxyLink("invalid"); e == nil {
		t.Fatal("bad secret accepted")
	}
}

type fakeProcess struct {
	alive   atomic.Bool
	stopped atomic.Bool
}

func (p *fakeProcess) Alive() bool { return p.alive.Load() }
func (p *fakeProcess) Stop()       { p.stopped.Store(true); p.alive.Store(false) }

type fakeRunner struct{ processes []*fakeProcess }

func (r *fakeRunner) Start(program string, args []string, dir string, input []byte, log string) (Process, error) {
	p := &fakeProcess{}
	p.alive.Store(true)
	r.processes = append(r.processes, p)
	return p, nil
}

type fakeExtra struct{}

func (fakeExtra) Start(context.Context, string, DomainRules) (func(), error) { return func() {}, nil }
func (fakeExtra) Alive() bool                                                { return true }
func TestEngineFailedSelectionDoesNotClaimWorking(t *testing.T) {
	r := &fakeRunner{}
	root := "../../runtime"
	engine := NewEngine(root, t.TempDir(), r, fakeExtra{}, nil)
	engine.probe = func(ctx context.Context, p string) Check {
		return Check{Profile: p, Targets: []Target{{Name: "YouTube"}, {Name: "Discord"}}}
	}
	c := DefaultConfig()
	c.Telegram = false
	c.Method = "auto"
	if e := engine.Start(c, "", false, func(string) {}); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for engine.Snapshot().Status == "starting" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if engine.Snapshot().Status != "error" || engine.Snapshot().DPI {
		t.Fatal(engine.Snapshot())
	}
	engine.Stop()
	for _, p := range r.processes {
		if p.Alive() {
			t.Fatal("candidate process leaked")
		}
	}
}
func TestEngineCancellationReleasesCandidate(t *testing.T) {
	r := &fakeRunner{}
	engine := NewEngine("../../runtime", t.TempDir(), r, fakeExtra{}, nil)
	engine.probe = func(ctx context.Context, p string) Check { <-ctx.Done(); return Check{Profile: p} }
	c := DefaultConfig()
	c.Telegram = false
	engine.Start(c, "", false, func(string) {})
	time.Sleep(400 * time.Millisecond)
	engine.Stop()
	if engine.Snapshot().Status != "off" {
		t.Fatal(engine.Snapshot())
	}
	for _, p := range r.processes {
		if p.Alive() {
			t.Fatal("leaked process")
		}
	}
}
func TestSnapshotRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	SaveJSON(filepath.Join(dir, "current-data.json"), map[string]string{"revision": "../../evil"})
	if ActiveData(dir, "bundled") != "bundled" {
		t.Fatal("unsafe snapshot accepted")
	}
}
