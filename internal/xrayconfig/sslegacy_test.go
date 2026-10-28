package xrayconfig

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestOutboundFromSS_LegacyBase64HostPort(t *testing.T) {
	cases := []struct{ name, plain, host string }{
		{"IPv6", "aes-256-gcm:pass@[2001:db8::1]:8388", "2001:db8::1"},
		{"IPv4", "aes-256-gcm:pass@192.0.2.7:8388", "192.0.2.7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := url.Parse("ss://" + base64.StdEncoding.EncodeToString([]byte(c.plain)))
			if err != nil {
				t.Fatal(err)
			}
			_, server, _, err := outboundFromSS(u, "proxy")
			if err != nil {
				t.Fatal(err)
			}
			if server != c.host {
				t.Fatalf("server = %q, want %q", server, c.host)
			}
		})
	}
}
