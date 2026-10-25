package core

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestUpdateEnvelopeAuthenticatesPayloadAndRejectsTampering(t *testing.T) {
	data, err := os.ReadFile("testdata/signed-update.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	json.Unmarshal(data, &envelope)
	now := time.Unix(int64(envelope["signedAt"].(float64))+1, 0)
	payload, err := verifyEnvelopeAt(data, now)
	if err != nil {
		t.Fatal(err)
	}
	var release Release
	if json.Unmarshal(payload, &release) != nil || release.Code != 1 || release.Validate() != nil {
		t.Fatal("invalid authenticated payload")
	}
	// Legacy outer fields are not authoritative for new clients.
	envelope["url"] = "https://evil.example/evil.exe"
	outer, _ := json.Marshal(envelope)
	if verified, e := verifyEnvelopeAt(outer, now); e != nil || string(verified) != string(payload) {
		t.Fatal("outer fields overrode signed payload")
	}
	for _, field := range []string{"signed", "signature", "keyId"} {
		var changed map[string]any
		json.Unmarshal(data, &changed)
		changed[field] = "AAAA"
		bad, _ := json.Marshal(changed)
		if _, e := verifyEnvelopeAt(bad, now); e == nil {
			t.Fatalf("tampered %s accepted", field)
		}
	}
	if _, e := verifyEnvelopeAt(data, now.Add(367*24*time.Hour)); e == nil {
		t.Fatal("expired signature accepted")
	}
	if _, e := verifyEnvelopeAt(data, now.Add(-time.Hour)); e == nil {
		t.Fatal("future metadata accepted")
	}
	if _, e := verifyEnvelopeAt([]byte(`{"versionCode":123}`), now); e == nil {
		t.Fatal("unsigned update accepted")
	}
}
