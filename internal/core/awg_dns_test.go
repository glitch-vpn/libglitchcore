//go:build !no_awg

package core

import (
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
)

// A rung of awg's resolver ladder with no IPv4 server the TUN takes falls
// through to the next, down to 1.1.1.1, rather than leave the tunnel with none.
func TestAwgTunDNS_SkipsARungWithNoIPv4Server(t *testing.T) {
	// Made-up keys.
	const link = "wireguard://gTsOy%2FCY9QScEmonjo7Wt6yF7WxLJXOBgpd24MmUH0Y%3D@203.0.113.7:51820" +
		"?publickey=kVNWJ0pOFM11%2Fp62BQNCmJQIffiVca8AipT6DTXxeVA%3D&address=10.0.0.2&dns="
	cases := []struct{ name, plainServer, linkDNS, want string }{
		{"an IPv6-only dns", "", "2606:4700:4700::1111", "1.1.1.1"},
		{"a hostname dns", "", "dns.example", "1.1.1.1"},
		{"a dns with an IPv4 server", "", "9.9.9.9,2606:4700:4700::1111", "9.9.9.9, 2606:4700:4700::1111"},
		{"no dns", "", "", "1.1.1.1"},
		{"a plain server first", "8.8.8.8", "9.9.9.9", "8.8.8.8"},
		{"an IPv6 plain server falls to dns", "2001:4860:4860::8888", "9.9.9.9", "9.9.9.9"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ini, err := awgconfig.NormalizeToINI(link + c.linkDNS)
			if err != nil {
				t.Fatal(err)
			}
			if got := awgTunDNS(c.plainServer, awgconfig.DNS(ini)); got != c.want {
				t.Fatalf("awgTunDNS = %q, want %q", got, c.want)
			}
		})
	}
}
