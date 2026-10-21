package mihomoconfig

import (
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

const (
	testVLESSLink  = "vless://" + testUUID + "@203.0.113.5:443?type=tcp&"
	testTrojanLink = "trojan://made-up-password@203.0.113.5:443?"
)

func TestCertChecks_VLESSAndTrojan(t *testing.T) {
	cases := map[string]struct {
		link string
		want map[string]any
	}{
		"vless_allowInsecure":  {testVLESSLink + "security=tls&allowInsecure=1", map[string]any{"skip-cert-verify": true}},
		"vless_insecure":       {testVLESSLink + "security=tls&insecure=true", map[string]any{"skip-cert-verify": true}},
		"vless_allow_insecure": {testVLESSLink + "security=tls&allow_insecure=1", map[string]any{"skip-cert-verify": true}},
		"vless_pinned": {
			testVLESSLink + "security=tls&sni=a.example.com&pcs=" + testCertPin + "&vcn=cert.example.com",
			map[string]any{"servername": "a.example.com", "fingerprint": testCertPin, "name-cert-verify": "cert.example.com", "skip-cert-verify": nil},
		},
		"vless_reality_has_no_certificate": {
			testVLESSLink + "security=reality&pbk=gdtgDEXry6dpwsJIyDnd6qVxUDMk9jRAthZnqHyDIUI&sid=455f&sni=a.com&allowInsecure=1",
			map[string]any{"skip-cert-verify": nil},
		},
		"trojan_allowInsecure_true": {testTrojanLink + "allowInsecure=true", map[string]any{"skip-cert-verify": true}},
		"trojan_insecure":           {testTrojanLink + "insecure=1", map[string]any{"skip-cert-verify": true}},
		"trojan_pinned": {
			testTrojanLink + "sni=a.example.com&pcs=" + testCertPin + "&vcn=cert.example.com",
			map[string]any{"sni": "a.example.com", "fingerprint": testCertPin, "name-cert-verify": "cert.example.com"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := ProxyMapFromLink(c.link)
			if err != nil {
				t.Fatalf("ProxyMapFromLink: %v", err)
			}
			wantFields(t, p, c.want)
		})
	}
}

func TestCertChecks_VLESSAndTrojanRefuseTwoPins(t *testing.T) {
	for name, link := range map[string]string{
		"vless":  testVLESSLink + "security=tls&pcs=" + testCertPin + "," + testCertPin,
		"trojan": testTrojanLink + "vcn=a.example.com,b.example.com",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ProxyMapFromLink(link); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

// mihomo's own parser takes what the builders hand it.
func TestCertChecks_ReachMihomosParser(t *testing.T) {
	links := []string{
		testVLESSLink + "security=tls&sni=a.example.com&allowInsecure=1#v",
		testTrojanLink + "sni=a.example.com&pcs=" + testCertPin + "&vcn=cert.example.com#t",
	}
	cfg, err := BuildConfig(links, Inbound{MixedPort: 17890}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	for _, name := range []string{"v", "t"} {
		if _, ok := cfg.Proxies[name]; !ok {
			t.Fatalf("proxy %q missing; have %v", name, cfg.Proxies)
		}
	}
}
