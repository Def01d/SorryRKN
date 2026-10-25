package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const Version = "1.4.0"
const VersionCode = 10400
const UpdateURL = "https://raw.githubusercontent.com/Def01d/SorryRKN/main/windows-update.json"

type Config struct {
	DPI             bool              `json:"dpi"`
	Telegram        bool              `json:"telegram"`
	Extras          bool              `json:"extra_sites"`
	Method          string            `json:"method"`
	ProtectedSecret string            `json:"protected_secret"`
	SavedProfile    string            `json:"last_profile"`
	AutoData        bool              `json:"auto_data"`
	GeoDomains      []string          `json:"geo_domains,omitempty"`
	DirectDomains   []string          `json:"direct_domains,omitempty"`
	DNSProfile      string            `json:"dns_profile,omitempty"`
	DNSCheckStartup *bool             `json:"dns_check_startup,omitempty"`
	ServiceDNS      map[string]string `json:"service_dns,omitempty"`
	Recovered       bool              `json:"-"`
	LoadError       string            `json:"-"`
}

func (c Config) DNSAutoCheck() bool { return c.DNSCheckStartup == nil || *c.DNSCheckStartup }

func DefaultConfig() Config { return Config{DPI: true, Telegram: true, Method: "auto", AutoData: true} }
func LoadConfig(path string) Config {
	b, e := readConfigBytes(path)
	if e == nil {
		if c, err := decodeConfig(b); err == nil {
			return c
		}
	}
	backup, backupError := readConfigBytes(path + ".bak")
	if backupError == nil {
		if c, err := decodeConfig(backup); err == nil {
			c.Recovered = true
			return c
		}
	}
	c := DefaultConfig()
	if !os.IsNotExist(e) || !os.IsNotExist(backupError) {
		c.LoadError = "Не удалось прочитать настройки и резервную копию. Файлы сохранены без изменений; восстановите config.json или config.json.bak."
	}
	return c
}

func readConfigBytes(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if len(b) > 1024*1024 {
		return nil, errors.New("settings file too large")
	}
	return b, e
}
func decodeConfig(b []byte) (Config, error) {
	c := DefaultConfig()
	var object map[string]json.RawMessage
	if json.Unmarshal(b, &object) != nil || object == nil {
		return c, errors.New("invalid settings object")
	}
	if e := json.Unmarshal(b, &c); e != nil {
		return c, e
	}
	if c.Method == "" {
		c.Method = "auto"
	}
	return c, nil
}
func SaveJSON(path string, value any) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	data, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	switch value.(type) {
	case Config, *Config:
		next, err := decodeConfig(data)
		if err != nil {
			return err
		}
		backup := data
		if previous, err := readConfigBytes(path); err == nil {
			if old, err := decodeConfig(previous); err == nil {
				if old.ProtectedSecret != "" || next.ProtectedSecret == "" {
					backup = previous
				}
			} else {
				backup = nil
			}
		}
		if backup != nil {
			if err := SaveJSON(path+".bak", json.RawMessage(backup)); err != nil {
				return err
			}
		}
	}
	temp := path + ".part"
	defer os.Remove(temp)
	if e = os.WriteFile(temp, data, 0600); e != nil {
		return e
	}
	if e = os.Rename(temp, path); e != nil {
		return e
	}
	return nil
}
func NewSecret() (string, error) {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func ValidSecret(value string) bool { b, e := hex.DecodeString(value); return e == nil && len(b) == 16 }
func ProxyLink(secret string) (string, error) {
	if !ValidSecret(secret) {
		return "", errors.New("invalid proxy secret")
	}
	return "tg://proxy?server=127.0.0.1&port=1443&secret=dd" + secret, nil
}
