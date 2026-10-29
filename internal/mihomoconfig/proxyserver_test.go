package mihomoconfig

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	mihomoAdapter "github.com/metacubex/mihomo/adapter"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// YWxpY2U6czNjcmV0 is base64 of the made-up alice:s3cret.
func TestSocksLinks_BuildMihomoOutbounds(t *testing.T) {
	cases := []struct {
		name, link string
		want       map[string]any
	}{
		{
			name: "v2rayN socks, base64 userinfo",
			link: "socks://YWxpY2U6czNjcmV0@203.0.113.7:1080#Home",
			want: map[string]any{"type": "socks5", "server": "203.0.113.7", "port": 1080, "username": "alice", "password": "s3cret", "udp": true},
		},
		{
			name: "socks5 without a login",
			link: "socks5://203.0.113.7:1080",
			want: map[string]any{"type": "socks5", "server": "203.0.113.7", "port": 1080, "udp": true},
		},
		{
			name: "Hiddify socks5h, plain userinfo",
			link: "socks5h://alice:s3cret@[2001:db8::7]:1081",
			want: map[string]any{"type": "socks5", "server": "2001:db8::7", "port": 1081, "username": "alice", "password": "s3cret", "udp": true},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := ProxyMapFromLink(c.link)
			if err != nil {
				t.Fatalf("ProxyMapFromLink: %v", err)
			}
			c.want["name"] = "probe"
			if !reflect.DeepEqual(p, c.want) {
				t.Fatalf("proxy = %v\nwant    %v", p, c.want)
			}
			if _, err := BuildConfig([]string{c.link}, Inbound{MixedPort: 17890}, Options{}, routing.Profile{}); err != nil {
				t.Fatalf("mihomo refuses the proxy: %v", err)
			}
		})
	}
}

func TestProxyLinks_MihomoRefusals(t *testing.T) {
	for name, link := range map[string]string{
		"socks4":                          "socks4://203.0.113.7:1080",
		"http, whose UDP would go direct": "http://YWxpY2U6czNjcmV0@203.0.113.7:8080#Web",
		"https, the same":                 "https://alice:s3cret@203.0.113.7:443?sni=front.example.com&pcs=" + testCertPin,
		"socks without a port":            "socks5://alice:s3cret@203.0.113.7",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ProxyMapFromLink(link)
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Fatalf("error carries the password: %v", err)
			}
			if _, err := BuildConfig([]string{link}, Inbound{MixedPort: 17890}, Options{}, routing.Profile{}); err == nil {
				t.Fatal("BuildConfig took the link")
			}
		})
	}
}

// mihomo skips a rule whose target cannot carry UDP and sends the flow on to
// the next rule, which ends at DIRECT, so every outbound the core builds must
// carry it.
func TestEveryOutboundCarriesUDP(t *testing.T) {
	vmess := "vmess://" + base64.StdEncoding.EncodeToString([]byte(
		`{"v":"2","ps":"vm","add":"203.0.113.5","port":"443","id":"`+testUUID+`","aid":"0","net":"ws","tls":"tls","sni":"a.example.com"}`))
	wireguard := "[Interface]\nPrivateKey = gTsOy/CY9QScEmonjo7Wt6yF7WxLJXOBgpd24MmUH0Y=\nAddress = 10.0.0.2/32\n" +
		"[Peer]\nPublicKey = kVNWJ0pOFM11/p62BQNCmJQIffiVca8AipT6DTXxeVA=\nEndpoint = 203.0.113.5:51820\n"
	for name, link := range map[string]string{
		"vless reality": "vless://" + testUUID + "@203.0.113.5:443?type=tcp&security=reality&sni=www.example.com&pbk=gdtgDEXry6dpwsJIyDnd6qVxUDMk9jRAthZnqHyDIUI&sid=455f9e232c6fb72d&flow=xtls-rprx-vision",
		"vless ws tls":  "vless://" + testUUID + "@203.0.113.5:443?type=ws&security=tls&sni=cdn.example.com&path=%2Fws",
		"vmess":         vmess,
		"shadowsocks":   "ss://aes-128-gcm:pass@203.0.113.5:8388",
		"trojan":        "trojan://secret@203.0.113.5:443?sni=example.com",
		"hysteria2":     "hysteria2://pass@203.0.113.5:443?sni=example.com",
		"tuic":          "tuic://" + testUUID + ":pw@203.0.113.5:443?sni=example.com&pcs=" + testCertPin,
		"anytls":        "anytls://pass@203.0.113.5:443?sni=example.com",
		"wireguard":     awgconfig.EncodeLink(wireguard, "wg"),
		"wireguard uri": "wg://203.0.113.5:51820?pk=gTsOy/CY9QScEmonjo7Wt6yF7WxLJXOBgpd24MmUH0Y=&pub=kVNWJ0pOFM11/p62BQNCmJQIffiVca8AipT6DTXxeVA=&ip=10.0.0.2&reserved=1,2,3",
		"socks5":        "socks5://alice:s3cret@203.0.113.5:1080",
	} {
		t.Run(name, func(t *testing.T) {
			p, err := ProxyMapFromLink(link)
			if err != nil {
				t.Fatalf("ProxyMapFromLink: %v", err)
			}
			proxy, err := mihomoAdapter.ParseProxy(p)
			if err != nil {
				t.Fatalf("mihomo refuses the proxy: %v", err)
			}
			defer proxy.Close()
			if !proxy.SupportUDP() {
				t.Fatalf("%s outbound carries no UDP", p["type"])
			}
		})
	}
}
