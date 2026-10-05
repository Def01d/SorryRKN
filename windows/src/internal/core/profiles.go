package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Profile struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Args []string `json:"args"`
}
type Catalog struct {
	Revision string    `json:"revision"`
	Profiles []Profile `json:"profiles"`
}

var allowedFlags = map[string]bool{}

func init() {
	for _, s := range strings.Fields("new wf-tcp wf-udp filter-tcp filter-udp filter-l7 filter-l3 filter-ip ip-id hostlist hostlist-domains hostlist-exclude hostlist-exclude-domains ipset ipset-exclude dpi-desync dpi-desync-ttl dpi-desync-ttl6 dpi-desync-autottl dpi-desync-autottl6 dpi-desync-repeats dpi-desync-fooling dpi-desync-split-pos dpi-desync-split-seqovl dpi-desync-split-seqovl-pattern dpi-desync-fake-tls dpi-desync-fake-quic dpi-desync-fake-http dpi-desync-fake-discord dpi-desync-fake-stun dpi-desync-fake-unknown-udp dpi-desync-fake-unknown dpi-desync-fake-tls-mod dpi-desync-any-protocol dpi-desync-cutoff dpi-desync-fakedsplit-pattern dpi-desync-fake-tls-offset dpi-desync-hostfakesplit-mod dpi-desync-hostfakesplit-midhost dpi-desync-hostfakesplit-fakeseq dpi-desync-badseq-increment dpi-desync-badack-increment dpi-desync-fake-tcp-mod dpi-desync-fake-tcp dpi-desync-fake-syndata dpi-desync-fake-unknown-tcp dpi-desync-start") {
		allowedFlags[s] = true
	}
}

var marker = regexp.MustCompile(`(?i)"%BIN%winws\.exe"`)

func ParseBAT(name, text string) (Profile, error) {
	var command strings.Builder
	found := false
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		if !found {
			loc := marker.FindStringIndex(line)
			if loc == nil {
				continue
			}
			line = line[loc[1]:]
			found = true
		}
		line = strings.TrimSpace(line)
		continued := strings.HasSuffix(line, "^")
		command.WriteString(strings.TrimSuffix(line, "^"))
		command.WriteByte(' ')
		if !continued {
			break
		}
	}
	if !found {
		return Profile{}, errors.New("no winws invocation")
	}
	text = command.String()
	for _, key := range []string{"%GameFilterTCP%", "%GameFilterUDP%", "%GameFilter%"} {
		text = strings.ReplaceAll(text, key, "12")
	}
	text = strings.ReplaceAll(text, "%BIN%", "@BIN@/")
	text = strings.ReplaceAll(text, "%LISTS%", "@LISTS@/")
	args, e := splitArgs(text)
	if e != nil {
		return Profile{}, e
	}
	if len(args) < 3 || len(args) > 400 {
		return Profile{}, errors.New("invalid argument count")
	}
	for _, arg := range args {
		if e = validateArg(arg); e != nil {
			return Profile{}, e
		}
	}
	id := strings.ToLower(strings.TrimSuffix(name, ".bat"))
	id = strings.ReplaceAll(id, " ", "-")
	return Profile{ID: id, Name: strings.TrimSuffix(strings.TrimPrefix(name, "general"), ".bat"), Args: args}, nil
}
func splitArgs(text string) ([]string, error) {
	var out []string
	var token strings.Builder
	quoted := false
	for _, r := range text {
		if r == '"' {
			quoted = !quoted
			continue
		}
		if (r == ' ' || r == '\t') && !quoted {
			if token.Len() > 0 {
				out = append(out, token.String())
				token.Reset()
			}
		} else {
			token.WriteRune(r)
		}
	}
	if quoted {
		return nil, errors.New("unclosed quote")
	}
	if token.Len() > 0 {
		out = append(out, token.String())
	}
	return out, nil
}
func validateArg(arg string) error {
	key, value, _ := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
	if !strings.HasPrefix(arg, "--") || !allowedFlags[key] || len(arg) > 4096 || strings.ContainsAny(arg, "%\x00\r\n&|<>`") {
		return fmt.Errorf("unsupported parameter: %s", key)
	}
	if strings.Contains(value, "@") {
		var prefix string
		for _, p := range []string{"@BIN@/", "@LISTS@/"} {
			if strings.HasPrefix(value, p) {
				prefix = p
			}
		}
		file := strings.TrimPrefix(value, prefix)
		if prefix == "" || file == "" || strings.ContainsAny(file, "/\\:") || strings.Contains(file, "..") {
			return errors.New("unsafe asset path")
		}
		if prefix == "@BIN@/" && !strings.HasSuffix(file, ".bin") {
			return errors.New("binary payload must be .bin")
		}
		if prefix == "@LISTS@/" && !strings.HasSuffix(file, ".txt") {
			return errors.New("host list must be .txt")
		}
	}
	return nil
}
func ResolveArgs(p Profile, dataRoot, binRoot string) ([]string, error) {
	var args []string
	for _, arg := range p.Args {
		if e := validateArg(arg); e != nil {
			return nil, e
		}
		for _, item := range []struct{ Prefix, Root string }{{"@BIN@/", binRoot}, {"@LISTS@/", filepath.Join(dataRoot, "lists")}} {
			if i := strings.Index(arg, item.Prefix); i >= 0 {
				file := arg[i+len(item.Prefix):]
				path := filepath.Join(item.Root, file)
				if item.Prefix == "@BIN@/" {
					preferred := filepath.Join(dataRoot, "bin", file)
					if _, e := os.Stat(preferred); e == nil {
						path = preferred
					}
				}
				if _, e := os.Stat(path); e != nil {
					return nil, fmt.Errorf("missing asset: %s", file)
				}
				arg = arg[:i] + path
			}
		}
		args = append(args, arg)
	}
	return args, nil
}
func LoadCatalog(root string) (Catalog, error) {
	var c Catalog
	b, e := os.ReadFile(filepath.Join(root, "profiles.json"))
	if e != nil {
		return c, e
	}
	if e = json.Unmarshal(b, &c); e != nil {
		return c, e
	}
	if len(c.Profiles) == 0 || len(c.Profiles) > 50 {
		return c, errors.New("invalid catalog size")
	}
	for _, p := range c.Profiles {
		for _, a := range p.Args {
			if e = validateArg(a); e != nil {
				return c, e
			}
		}
	}
	return c, nil
}
func CatalogFromDir(root, revision string) (Catalog, error) {
	files, e := filepath.Glob(filepath.Join(root, "general*.bat"))
	if e != nil {
		return Catalog{}, e
	}
	sort.Strings(files)
	c := Catalog{Revision: revision}
	for _, file := range files {
		b, e := os.ReadFile(file)
		if e != nil {
			return c, e
		}
		p, e := ParseBAT(filepath.Base(file), string(b))
		if e != nil {
			return c, fmt.Errorf("%s: %w", filepath.Base(file), e)
		}
		if p.Name == "" {
			p.Name = "Основной"
		}
		c.Profiles = append(c.Profiles, p)
	}
	sort.SliceStable(c.Profiles, func(i, j int) bool { return priority(c.Profiles[i].ID) < priority(c.Profiles[j].ID) })
	return c, nil
}
func priority(id string) int {
	for i, s := range []string{"general", "general-(alt)", "general-(alt2)", "general-(alt5)", "general-(fake-tls-auto)", "general-(simple-fake)"} {
		if id == s {
			return i
		}
	}
	return 99
}
func Candidates(c Catalog, config Config, extended bool) []Profile {
	var out []Profile
	seen := map[string]bool{}
	add := func(id string) {
		for _, p := range c.Profiles {
			if p.ID == id && !seen[id] {
				out = append(out, p)
				seen[id] = true
			}
		}
	}
	if config.Method != "auto" {
		add(config.Method)
		return out
	}
	add(config.SavedProfile)
	for _, p := range c.Profiles {
		add(p.ID)
	}
	if !extended && len(out) > 6 {
		out = out[:6]
	}
	return out
}
