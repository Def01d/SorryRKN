package tunnel

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

const fakeUUID = "137001ca-1c37-4f48-a2d3-3d72253b051c"

func samples() []string {
	ss := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:example-pass"))
	vm := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"add":"127.0.0.1","port":"12345","id":"%s","aid":"0","net":"ws","tls":"tls","sni":"example.org","path":"/test","ps":"Fixture"}`, fakeUUID)))
	key := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("A", 32)))
	return []string{
		"vless://" + fakeUUID + "@127.0.0.1:12345?security=reality&pbk=" + key + "&sid=0123&sni=example.org&fp=chrome&flow=xtls-rprx-vision#Reality",
		"vless://" + fakeUUID + "@127.0.0.1:12345?type=grpc&serviceName=test&security=tls#GRPC",
		"vmess://" + vm, "trojan://abc@127.0.0.1:12345?sni=example.org&type=ws&path=/test",
		"ss://" + ss + "@127.0.0.1:12345#Example", "hy2://pass@127.0.0.1:12345?sni=example.org",
	}
}
func TestMixedSubscription(t *testing.T) {
	input := append(samples(), "vless://"+fakeUUID+"@127.0.0.1:443?type=xhttp", "ss://invalid", "trojan://test@127.0.0.1:12345?allowInsecure=1", samples()[0])
	encoded := base64.RawURLEncoding.EncodeToString([]byte(strings.Join(input, "\n")))
	result, err := ImportWithReport(context.Background(), encoded)
	if err != nil || result.Skipped != 3 || len(result.Profiles) != len(samples()) {
		t.Fatalf("mixed subscription: %+v %v", result, err)
	}
	for _, p := range result.Profiles {
		if _, err := engineConfig(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
}
