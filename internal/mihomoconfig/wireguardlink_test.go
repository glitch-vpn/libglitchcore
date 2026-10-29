package mihomoconfig

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// Made-up keys.
const (
	wgPrivateKey = "gTsOy/CY9QScEmonjo7Wt6yF7WxLJXOBgpd24MmUH0Y="
	wgPublicKey  = "kVNWJ0pOFM11/p62BQNCmJQIffiVca8AipT6DTXxeVA="
)

func TestWireGuardLinks_ReachMihomosWireGuardOutbound(t *testing.T) {
	esc := url.QueryEscape
	cases := []struct {
		name, link string
		want       map[string]any
		awg        map[string]any
		proxyName  string
	}{
		{
			name: "v2rayNG with reserved bytes",
			link: "wireguard://" + esc(wgPrivateKey) + "@203.0.113.7:2408?publickey=" + esc(wgPublicKey) +
				"&reserved=12,34,56&address=" + esc("172.16.0.2/32,2606:4700:110:8a36::2/128") + "&mtu=1280#WARP+One",
			want: map[string]any{"server": "203.0.113.7", "port": 2408, "reserved": []int{12, 34, 56}, "mtu": 1280,
				"ip": "172.16.0.2", "ipv6": "2606:4700:110:8a36::2"},
			proxyName: "WARP One",
		},
		{
			name: "v2rayNG's all-zero reserved sends none",
			link: "wireguard://" + esc(wgPrivateKey) + "@203.0.113.7:2408?publickey=" + esc(wgPublicKey) + "&reserved=0,0,0&address=172.16.0.2/32",
			want: map[string]any{"ip": "172.16.0.2"},
		},
		{
			name: "Hiddify wg:// with AmneziaWG keys",
			link: "wg://203.0.113.7:51820?pk=" + wgPrivateKey + "&pub=" + wgPublicKey + "&ip=10.8.0.2&keepalive=25&jc=4&jmin=40&jmax=70&s1=15&h1=100-200&i1=<b+0xf6ab>",
			want: map[string]any{"ip": "10.8.0.2", "persistent-keepalive": 25},
			awg:  map[string]any{"jc": 4, "jmin": 40, "jmax": 70, "s1": 15, "h1": "100-200", "i1": "<b 0xf6ab>"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := ProxyMapFromLink(c.link)
			if err != nil {
				t.Fatalf("ProxyMapFromLink: %v", err)
			}
			if p["type"] != "wireguard" || p["private-key"] != wgPrivateKey || p["public-key"] != wgPublicKey {
				t.Fatalf("proxy = %v", p)
			}
			for k, v := range c.want {
				if !reflect.DeepEqual(p[k], v) {
					t.Errorf("%s = %v, want %v", k, p[k], v)
				}
			}
			if _, ok := c.want["reserved"]; !ok && p["reserved"] != nil {
				t.Errorf("reserved = %v, want none", p["reserved"])
			}
			opt, _ := p["amnezia-wg-option"].(map[string]any)
			if c.awg == nil && opt != nil {
				t.Errorf("amnezia-wg-option = %v, want plain WireGuard", opt)
			}
			for k, v := range c.awg {
				if opt[k] != v {
					t.Errorf("amnezia-wg-option[%s] = %v, want %v", k, opt[k], v)
				}
			}
			if _, err := BuildConfig([]string{c.link}, Inbound{MixedPort: 17890}, Options{}, routing.Profile{}); err != nil {
				t.Fatalf("mihomo refuses the proxy: %v", err)
			}
			if c.proxyName != "" {
				if names := ProxyNames([]string{c.link}); names[0] != c.proxyName {
					t.Errorf("name = %q, want %q", names[0], c.proxyName)
				}
			}
		})
	}
}
