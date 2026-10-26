package xrayconfig

import (
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
)

func vmessJSONLink(fields string) string {
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(
		`{"v":"2","ps":"t","add":"127.0.0.1","port":"443","id":"49c8fb89-9418-4ff4-8505-7a2772fc4b71",`+fields+`}`))
}

// A capability gap is returned only when no safety refusal applies to the
// link, whichever check the builder reaches first.
func TestBuildConfig_CapabilityGapNeverMasksASafetyRefusal(t *testing.T) {
	const id = "49c8fb89-9418-4ff4-8505-7a2772fc4b71"
	safety := []string{
		"trojan://secret@127.0.0.1:443?security=tls&allowInsecure=1&headerType=http",
		"trojan://secret@127.0.0.1:443?security=tls&allowInsecure=1&type=h2",
		fmt.Sprintf("vless://%s@127.0.0.1:443?type=tcp&headerType=http&security=tls&allowInsecure=1", id),
		fmt.Sprintf("vless://%s@127.0.0.1:443?type=h2&security=tls&allowInsecure=1", id),
		fmt.Sprintf("vless://%s@8.8.8.8:443?type=tcp&headerType=http&security=none", id),
		fmt.Sprintf("vless://%s@8.8.8.8:443?type=h2&security=none", id),
		fmt.Sprintf("vless://%s@127.0.0.1:443?type=h2&security=bogus", id),
		vmessJSONLink(`"aid":"2","net":"tcp","tls":"tls","insecure":"1"`),
		vmessJSONLink(`"aid":"2","net":"tcp","tls":"","scy":"none"`),
		vmessJSONLink(`"aid":"2","net":"h2","tls":"tls","insecure":"1"`),
	}
	for _, link := range safety {
		_, err := BuildConfig([]string{link}, BalancerOptions{}, RoutingProfile{}, "none")
		var gap NotCarriedError
		if err == nil || errors.As(err, &gap) {
			t.Errorf("%.40s...: err = %v, want a safety refusal that is not a capability gap", link, err)
		}
	}

	capability := []string{
		vmessJSONLink(`"aid":"2","net":"tcp","tls":"tls"`),
		fmt.Sprintf("vless://%s@127.0.0.1:443?type=h2&security=tls", id),
		fmt.Sprintf("vless://%s@127.0.0.1:443?type=tcp&headerType=http&security=tls", id),
		"trojan://secret@127.0.0.1:443?security=tls&headerType=http",
	}
	for _, link := range capability {
		_, err := BuildConfig([]string{link}, BalancerOptions{}, RoutingProfile{}, "none")
		var gap NotCarriedError
		if !errors.As(err, &gap) {
			t.Errorf("%.40s...: err = %v, want a capability gap", link, err)
		}
	}
}
