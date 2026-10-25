package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsRecoveryKeepsSecretAndServiceChoices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	first := DefaultConfig()
	first.ProtectedSecret = "synthetic-protected-value"
	first.ServiceDNS = map[string]string{"chatgpt": "auto", "gemini": "geohide-eu"}
	if err := SaveJSON(path, first); err != nil {
		t.Fatal(err)
	}
	changed := first
	changed.Method = "manual-fixture"
	if err := SaveJSON(path, changed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"broken":`), 0600); err != nil {
		t.Fatal(err)
	}
	recovered := LoadConfig(path)
	if !recovered.Recovered || recovered.LoadError != "" || recovered.ProtectedSecret != first.ProtectedSecret || recovered.ServiceDNS["gemini"] != "geohide-eu" {
		t.Fatal("settings not recovered intact")
	}
	if err := SaveJSON(path, recovered); err != nil {
		t.Fatal(err)
	}
	loaded := LoadConfig(path)
	if loaded.Recovered || loaded.LoadError != "" || loaded.ProtectedSecret != first.ProtectedSecret {
		t.Fatal("recovered settings not persisted")
	}
}
func TestBrokenSettingsNeverBecomeFreshInstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	fresh := LoadConfig(path)
	if fresh.LoadError != "" {
		t.Fatal("fresh install rejected")
	}
	for _, bad := range []string{`null`, `[]`, `{"dns_check_startup":"wrong type"}`, `{"broken":`} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if got := LoadConfig(path); got.LoadError == "" {
			t.Fatal("broken settings would generate a new secret", bad)
		}
		bytes, _ := os.ReadFile(path)
		if string(bytes) != bad {
			t.Fatal("broken original overwritten")
		}
	}
}

func TestFirstSettingsWriteBacksUpOriginalSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := DefaultConfig()
	c.ProtectedSecret = "synthetic-protected-first-secret"
	if err := SaveJSON(path, c); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	recovered := LoadConfig(path)
	if !recovered.Recovered || recovered.ProtectedSecret != c.ProtectedSecret {
		t.Fatal("first secret was not backed up")
	}
}
