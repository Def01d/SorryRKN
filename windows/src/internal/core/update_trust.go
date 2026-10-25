package core

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

//go:embed update_trust.json
var updateTrustJSON []byte

func VerifyEnvelope(data []byte) ([]byte, error) { return verifyEnvelopeAt(data, time.Now()) }
func verifyEnvelopeAt(data []byte, now time.Time) ([]byte, error) {
	var trust struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	var value struct {
		Signed    string `json:"signed"`
		Signature string `json:"signature"`
		KeyID     string `json:"keyId"`
		SignedAt  int64  `json:"signedAt"`
		Expires   int64  `json:"expires"`
	}
	bad := errors.New("подпись данных обновления недействительна")
	if len(data) > 65536 || json.Unmarshal(updateTrustJSON, &trust) != nil || json.Unmarshal(data, &value) != nil || value.KeyID != trust.KeyID || value.Signed == "" {
		return nil, bad
	}
	if value.SignedAt > now.Unix()+300 || value.Expires <= now.Unix() || value.Expires <= value.SignedAt || value.Expires-value.SignedAt > 366*86400 {
		return nil, errors.New("срок подписи обновления истёк или неверно время устройства")
	}
	der, e := base64.StdEncoding.Strict().DecodeString(trust.PublicKey)
	if e != nil {
		return nil, bad
	}
	key, e := x509.ParsePKIXPublicKey(der)
	if e != nil {
		return nil, bad
	}
	public, ok := key.(*ecdsa.PublicKey)
	if !ok || public.Curve.Params().BitSize != 256 {
		return nil, bad
	}
	signature, e := base64.StdEncoding.Strict().DecodeString(value.Signature)
	if e != nil {
		return nil, bad
	}
	message := fmt.Sprintf("SorryRKN-Envelope-v1\n%s\n%d\n%d\n%s", value.KeyID, value.SignedAt, value.Expires, value.Signed)
	digest := sha256.Sum256([]byte(message))
	if !ecdsa.VerifyASN1(public, digest[:], signature) {
		return nil, bad
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(value.Signed)
	if e != nil || !json.Valid(payload) {
		return nil, bad
	}
	return payload, nil
}
