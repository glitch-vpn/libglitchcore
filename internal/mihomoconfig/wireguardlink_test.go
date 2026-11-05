package mihomoconfig

import (
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/serverinfo"
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

const twoPeerINI = "[Interface]\nPrivateKey = " + wgPrivateKey + "\nAddress = 10.0.0.2/32\n\n" +
	"[Peer]\nPublicKey = " + wgPublicKey + "\nEndpoint = 203.0.113.7:51820\nAllowedIPs = 10.1.0.0/16\nPersistentKeepalive = 25\n\n" +
	"[Peer]\nPublicKey = " + wgPrivateKey + "\nPresharedKey = " + wgPublicKey + "\nEndpoint = 198.51.100.9:2408\n" +
	"AllowedIPs = 0.0.0.0/0, ::/0\nReserved = 7,8,9\nPersistentKeepalive = 15\n"

// Every [Peer] reaches mihomo's peers option, and the server event names the
// endpoint the outbound is named for: the first peer's.
func TestWireGuardConfig_EveryPeerReachesMihomo(t *testing.T) {
	p, err := ProxyMapFromLink(twoPeerINI)
	if err != nil {
		t.Fatalf("ProxyMapFromLink: %v", err)
	}
	peers, _ := p["peers"].([]map[string]any)
	if len(peers) != 2 {
		t.Fatalf("peers = %v, want two", p["peers"])
	}
	want := []map[string]any{
		{"server": "203.0.113.7", "port": 51820, "public-key": wgPublicKey, "allowed-ips": []string{"10.1.0.0/16"}},
		{"server": "198.51.100.9", "port": 2408, "public-key": wgPrivateKey, "pre-shared-key": wgPublicKey,
			"allowed-ips": []string{"0.0.0.0/0", "::/0"}, "reserved": []int{7, 8, 9}},
	}
	if !reflect.DeepEqual(peers, want) {
		t.Errorf("peers = %v\nwant %v", peers, want)
	}
	if p["server"] != "203.0.113.7" || p["port"] != 51820 {
		t.Errorf("server = %v:%v, want the first peer's", p["server"], p["port"])
	}
	if p["persistent-keepalive"] != 15 {
		t.Errorf("persistent-keepalive = %v, want the shortest, 15", p["persistent-keepalive"])
	}
	if _, ok := p["public-key"]; ok {
		t.Errorf("public-key = %v at the top level beside peers", p["public-key"])
	}
	if _, err := BuildConfig([]string{twoPeerINI}, Inbound{MixedPort: 17890}, Options{}, routing.Profile{}); err != nil {
		t.Fatalf("mihomo refuses the proxy: %v", err)
	}
	if got := serverinfo.FromLink(twoPeerINI, 0); got.Host != p["server"] || got.Port != p["port"] {
		t.Errorf("server event = %s:%d, dialled %v:%v", got.Host, got.Port, p["server"], p["port"])
	}
}

func TestWireGuardConfig_SeveralPeersNeedAllowedIPs(t *testing.T) {
	ini := "[Interface]\nPrivateKey = " + wgPrivateKey + "\nAddress = 10.0.0.2/32\n\n" +
		"[Peer]\nPublicKey = " + wgPublicKey + "\nEndpoint = 203.0.113.7:51820\nAllowedIPs = 10.1.0.0/16\n\n" +
		"[Peer]\nPublicKey = " + wgPublicKey + "\nEndpoint = 198.51.100.9:2408\n"
	_, err := ProxyMapFromLink(ini)
	if err == nil || !strings.Contains(err.Error(), "peer 2") || !strings.Contains(err.Error(), "AllowedIPs") {
		t.Fatalf("err = %v, want a refusal naming peer 2 and AllowedIPs", err)
	}
}
