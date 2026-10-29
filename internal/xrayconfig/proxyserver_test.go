package xrayconfig

import (
	"strings"
	"testing"
)

// YWxpY2U6czNjcmV0 is base64 of the made-up alice:s3cret.
func TestProxyLinks_BuildXrayOutbounds(t *testing.T) {
	cases := []struct {
		name, link, protocol string
		settings             []string
		tls                  bool
		serverName, pin      string
	}{
		{
			name: "v2rayN socks, base64 userinfo", link: "socks://YWxpY2U6czNjcmV0@203.0.113.7:1080#Home", protocol: "socks",
			settings: []string{`"address":"203.0.113.7"`, `"port":1080`, `"user":"alice"`, `"pass":"s3cret"`},
		},
		{
			name: "socks5 without a login", link: "socks5://203.0.113.7:1080", protocol: "socks",
			settings: []string{`"address":"203.0.113.7"`, `"user":""`},
		},
		{
			name: "Hiddify socks5h, plain userinfo", link: "socks5h://alice:s3cret@[2001:db8::7]:1081", protocol: "socks",
			settings: []string{`"address":"[2001:db8::7]"`, `"port":1081`, `"user":"alice"`, `"pass":"s3cret"`},
		},
		{
			name: "v2rayN http, base64 userinfo", link: "http://YWxpY2U6czNjcmV0@203.0.113.7:8080#Web", protocol: "http",
			settings: []string{`"address":"203.0.113.7"`, `"port":8080`, `"user":"alice"`, `"pass":"s3cret"`},
		},
		{
			name: "https with an sni and a pinned certificate", link: "https://alice:s3cret@203.0.113.7:443?sni=front.example.com&pcs=" + testPin,
			protocol: "http", settings: []string{`"port":443`, `"user":"alice"`},
			tls: true, serverName: "front.example.com", pin: testPin,
		},
		{
			name: "https without an sni", link: "https://203.0.113.7:8443", protocol: "http",
			settings: []string{`"port":8443`}, tls: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := buildLink(t, c.link)
			ob := res.Config.OutboundConfigs[0]
			if ob.Protocol != c.protocol || ob.Tag != OutboundTag {
				t.Fatalf("outbound = %s/%s", ob.Protocol, ob.Tag)
			}
			settings := string(*ob.Settings)
			for _, want := range c.settings {
				if !strings.Contains(settings, want) {
					t.Fatalf("settings = %s, want %s", settings, want)
				}
			}
			stream := ob.StreamSetting
			if !c.tls {
				if stream.Security != "" || stream.TLSSettings != nil {
					t.Fatalf("security = %q, want none", stream.Security)
				}
				return
			}
			if stream.Security != "tls" || stream.TLSSettings.ServerName != c.serverName || stream.TLSSettings.PinnedPeerCertSha256 != c.pin {
				t.Fatalf("tls = %q %+v", stream.Security, stream.TLSSettings)
			}
		})
	}
}

func TestProxyLinks_XrayRefusals(t *testing.T) {
	for name, link := range map[string]string{
		"socks4":                      "socks4://203.0.113.7:1080",
		"https skipping verification": "https://alice:s3cret@203.0.113.7:443?allowInsecure=1",
		"no port":                     "socks5://alice:s3cret@203.0.113.7",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := BuildConfig([]string{link}, BalancerOptions{}, RoutingProfile{}, "none")
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Fatalf("error carries the password: %v", err)
			}
		})
	}
}

// A pool of a proxy and a vless server stays on xray as one balancer.
func TestProxyLinks_ShareAPoolWithVless(t *testing.T) {
	res, err := BuildConfig([]string{
		"socks://YWxpY2U6czNjcmV0@203.0.113.7:1080",
		testVLESSLink + "security=tls&sni=a.example.com",
		"http://203.0.113.8:8080",
	}, BalancerOptions{}, RoutingProfile{}, "none")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if _, err := res.Config.Build(); err != nil {
		t.Fatalf("xray rejects the config: %v", err)
	}
	if got := strings.Join(res.Servers, ","); got != "203.0.113.7,203.0.113.5,203.0.113.8" {
		t.Fatalf("servers = %s", got)
	}
}
