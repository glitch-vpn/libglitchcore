package mihomoconfig

import "testing"

const vlessSecurityBase = "vless://00000000-0000-4000-8000-000000000000@203.0.113.10:443?type=tcp&sni=example.com&security="

func TestVlessProxy_RefusesAnUnknownSecurity(t *testing.T) {
	for _, security := range []string{"xtls", "ssl", "tls1.3", "%20xtls%20", "tlss"} {
		if _, err := ProxyMapFromLink(vlessSecurityBase + security); err == nil {
			t.Errorf("security=%s: carried, want refused", security)
		}
	}
}

func TestVlessProxy_CarriesTLSAndPlainSecurity(t *testing.T) {
	for _, tc := range []struct {
		security string
		tls      bool
	}{
		{"tls", true},
		{"%20TLS%20", true},
		{"none", false},
		{"", false},
	} {
		proxy, err := ProxyMapFromLink(vlessSecurityBase + tc.security)
		if err != nil {
			t.Fatalf("security=%q: %v", tc.security, err)
		}
		if got := proxy["tls"] == true; got != tc.tls {
			t.Errorf("security=%q: tls=%v, want %v", tc.security, got, tc.tls)
		}
	}
}
