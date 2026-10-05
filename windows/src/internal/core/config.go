package core

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

const Version = "1.0.0"
const VersionCode = 10000
const UpdateURL = "https://raw.githubusercontent.com/Def01d/SorryRKN/main/windows-update.json"

type Config struct {
	DPI             bool   `json:"dpi"`
	Telegram        bool   `json:"telegram"`
	Extras          bool   `json:"extra_sites"`
	Method          string `json:"method"`
	ProtectedSecret string `json:"protected_secret"`
	SavedProfile    string `json:"last_profile"`
	AutoData        bool   `json:"auto_data"`
}

func DefaultConfig() Config { return Config{DPI: true, Telegram: true, Method: "auto", AutoData: true} }
func LoadConfig(path string) Config {
	c := DefaultConfig()
	b, e := os.ReadFile(path)
	if e == nil {
		if json.Unmarshal(b, &c) != nil {
			return DefaultConfig()
		}
	}
	if c.Method == "" {
		c.Method = "auto"
	}
	return c
}
func SaveJSON(path string, value any) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	data, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	temp := path + ".part"
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
