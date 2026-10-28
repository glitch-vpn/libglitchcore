package mihomoconfig

import (
	"encoding/base64"
	"testing"
)

func TestSSProxy_LegacyBase64HostPort(t *testing.T) {
	cases := []struct{ name, plain, host string }{
		{"IPv6", "aes-256-gcm:pass@[2001:db8::1]:8388", "2001:db8::1"},
		{"IPv4", "aes-256-gcm:pass@192.0.2.7:8388", "192.0.2.7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := ssProxy("ss://"+base64.StdEncoding.EncodeToString([]byte(c.plain)), "n")
			if err != nil {
				t.Fatal(err)
			}
			if p["server"] != c.host || p["port"] != 8388 {
				t.Fatalf("server/port = %v/%v", p["server"], p["port"])
			}
		})
	}
}
