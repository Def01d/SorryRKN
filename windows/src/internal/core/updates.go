package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Release struct {
	Platform string `json:"platform"`
	Code     int    `json:"versionCode"`
	Name     string `json:"versionName"`
	URL      string `json:"url"`
	SHA      string `json:"sha256"`
	Size     int64  `json:"size"`
	Notes    string `json:"notes"`
}

func (r Release) Validate() error {
	u, e := url.Parse(r.URL)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Host != "raw.githubusercontent.com" || !strings.HasPrefix(u.Path, "/Def01d/SorryRKN/windows-v") {
		return errors.New("untrusted update URL")
	}
	if r.Platform != "windows-x64" || r.Code <= 0 || len(r.Name) > 40 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(r.SHA) || r.Size <= 0 || r.Size > 128*1024*1024 || len(r.Notes) > 4000 {
		return errors.New("invalid release manifest")
	}
	return nil
}
func HTTPClient() *http.Client {
	return &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" || len(via) > 5 {
			return errors.New("unsafe redirect")
		}
		return nil
	}}
}
func Fetch(ctx context.Context, client *http.Client, address string, limit int64) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", address, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "SorryRKN-Windows/"+Version)
	r, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if e != nil {
		return nil, e
	}
	if int64(len(b)) > limit {
		return nil, errors.New("response too large")
	}
	return b, nil
}
func CheckUpdate(ctx context.Context) (Release, error) {
	var r Release
	b, e := Fetch(ctx, HTTPClient(), UpdateURL, 16384)
	if e != nil {
		return r, e
	}
	if e = json.Unmarshal(b, &r); e != nil {
		return r, e
	}
	return r, r.Validate()
}
func DownloadUpdate(ctx context.Context, r Release, path string) error {
	if e := r.Validate(); e != nil {
		return e
	}
	client := HTTPClient()
	client.Timeout = 3 * time.Minute
	req, e := http.NewRequestWithContext(ctx, "GET", r.URL, nil)
	if e != nil {
		return e
	}
	response, e := client.Do(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	temp := path + ".part"
	file, e := os.Create(temp)
	if e != nil {
		return e
	}
	defer os.Remove(temp)
	hash := sha256.New()
	size, e := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, r.Size+1))
	file.Close()
	if e != nil {
		return e
	}
	if size != r.Size || hex.EncodeToString(hash.Sum(nil)) != r.SHA {
		return errors.New("download integrity check failed")
	}
	f, e := os.Open(temp)
	if e != nil {
		return e
	}
	header := make([]byte, 2)
	_, e = io.ReadFull(f, header)
	f.Close()
	if e != nil || !bytes.Equal(header, []byte("MZ")) {
		return errors.New("not a Windows executable")
	}
	return os.Rename(temp, path)
}
func ActiveData(data, fallback string) string {
	var p struct {
		Revision string `json:"revision"`
	}
	b, e := os.ReadFile(filepath.Join(data, "current-data.json"))
	if e != nil || json.Unmarshal(b, &p) != nil || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(p.Revision) {
		return fallback
	}
	path := filepath.Join(data, "snapshots", p.Revision)
	if _, e = LoadCatalog(path); e != nil {
		return fallback
	}
	return path
}
func UpdateData(ctx context.Context, data string) (string, error) {
	client := HTTPClient()
	refreshTelegram(ctx, client, data)
	var commit struct {
		SHA string `json:"sha"`
	}
	b, e := Fetch(ctx, client, "https://api.github.com/repos/Flowseal/zapret-discord-youtube/commits/main", 1000000)
	if e != nil {
		return "", e
	}
	if e = json.Unmarshal(b, &commit); e != nil || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(commit.SHA) {
		return "", errors.New("invalid upstream revision")
	}
	target := filepath.Join(data, "snapshots", commit.SHA)
	if _, e = LoadCatalog(target); e == nil {
		return commit.SHA, nil
	}
	temp := target + ".part"
	os.RemoveAll(temp)
	defer os.RemoveAll(temp)
	os.MkdirAll(filepath.Join(temp, "lists"), 0700)
	os.MkdirAll(filepath.Join(temp, "bin"), 0700)
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		}
		Truncated bool `json:"truncated"`
	}
	b, e = Fetch(ctx, client, "https://api.github.com/repos/Flowseal/zapret-discord-youtube/git/trees/"+commit.SHA, 1000000)
	if e != nil {
		return "", e
	}
	if e = json.Unmarshal(b, &tree); e != nil || tree.Truncated {
		return "", errors.New("invalid upstream tree")
	}
	raw := "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/" + commit.SHA + "/"
	catalog := Catalog{Revision: commit.SHA}
	assets := map[string]bool{}
	for _, entry := range tree.Tree {
		if entry.Type != "blob" || !regexp.MustCompile(`^general[^/\\]*\.bat$`).MatchString(entry.Path) {
			continue
		}
		b, e = Fetch(ctx, client, raw+url.PathEscape(entry.Path), 65536)
		if e != nil {
			return "", e
		}
		p, e := ParseBAT(entry.Path, string(b))
		if e != nil {
			continue
		}
		if p.Name == "" {
			p.Name = "Основной"
		}
		catalog.Profiles = append(catalog.Profiles, p)
		for _, arg := range p.Args {
			for _, prefix := range []string{"@BIN@/", "@LISTS@/"} {
				if i := strings.Index(arg, prefix); i >= 0 {
					name := arg[i+len(prefix):]
					directory := "bin/"
					if prefix == "@LISTS@/" {
						directory = "lists/"
					}
					assets[directory+name] = true
				}
			}
		}
	}
	sort.SliceStable(catalog.Profiles, func(i, j int) bool { return priority(catalog.Profiles[i].ID) < priority(catalog.Profiles[j].ID) })
	if len(catalog.Profiles) < 2 || len(catalog.Profiles) > 50 {
		return "", errors.New("no compatible strategy catalog")
	}
	var total int
	for file := range assets {
		limit := int64(1024 * 1024)
		if strings.HasPrefix(file, "bin/") {
			limit = 16384
		}
		if strings.HasSuffix(file, "-user.txt") {
			b = []byte{}
			if strings.Contains(file, "list-exclude-") {
				b = []byte("dns.comss.one\n")
			}
			if strings.Contains(file, "ipset-exclude-") {
				b = []byte("195.133.25.16\n")
			}
		} else {
			b, e = Fetch(ctx, client, raw+file, limit)
			if e != nil {
				return "", e
			}
		}
		total += len(b)
		if total > 12*1024*1024 {
			return "", errors.New("snapshot too large")
		}
		if e = os.WriteFile(filepath.Join(temp, filepath.FromSlash(file)), b, 0600); e != nil {
			return "", e
		}
	}
	if e = SaveJSON(filepath.Join(temp, "profiles.json"), catalog); e != nil {
		return "", e
	}
	if e = os.Rename(temp, target); e != nil {
		return "", e
	}
	if e = SaveJSON(filepath.Join(data, "current-data.json"), map[string]string{"revision": commit.SHA}); e != nil {
		return "", e
	}

	return commit.SHA, nil
}
func DecodeDomains(text string) []string {
	pattern := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,250})\.[a-z]{2,20}$`)
	seen := map[string]bool{}
	var result []string
	for _, line := range strings.Split(text, "\n") {
		s := strings.ToLower(strings.TrimSpace(line))
		if !pattern.MatchString(s) {
			continue
		}
		if strings.HasSuffix(s, ".com") {
			p := strings.TrimSuffix(s, ".com")
			n := 0
			for _, r := range p {
				if r >= 'a' && r <= 'z' {
					n++
				}
			}
			var decoded strings.Builder
			for _, r := range p {
				if r >= 'a' && r <= 'z' {
					r = (r-'a'-rune(n)%26+26)%26 + 'a'
				}
				decoded.WriteRune(r)
			}
			s = decoded.String() + ".co.uk"
		}
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func refreshTelegram(ctx context.Context, client *http.Client, data string) {
	// Only the declarative Telegram domain pool is refreshed, never Python code.
	var b []byte
	var e error
	var tgCommit struct {
		SHA string `json:"sha"`
	}
	if b, e = Fetch(ctx, client, "https://api.github.com/repos/Flowseal/tg-ws-proxy/commits/main", 1000000); e == nil && json.Unmarshal(b, &tgCommit) == nil && regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(tgCommit.SHA) {
		if b, e = Fetch(ctx, client, "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/"+tgCommit.SHA+"/.github/cfproxy-domains.txt", 65536); e == nil {
			if domains := DecodeDomains(string(b)); len(domains) >= 3 {
				SaveJSON(filepath.Join(data, "tg-domains.json"), domains)
			}
		}
	}
}
