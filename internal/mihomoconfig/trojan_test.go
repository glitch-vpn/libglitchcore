package mihomoconfig

import (
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

const trojanBase = "trojan://made-up-password@203.0.113.5:443?security=tls&sni=sni.example.com&"

func TestTrojanProxy_Transports(t *testing.T) {
	cases := map[string]struct {
		link string
		want map[string]any
	}{
		"tcp": {
			trojanBase + "type=tcp&headerType=none",
			map[string]any{"network": nil, "ws-opts": nil, "grpc-opts": nil},
		},
		"ws": {
			trojanBase + "type=ws&path=%2Fws&host=cdn.example.com",
			map[string]any{"network": "ws", "ws-opts": map[string]any{"path": "/ws", "headers": map[string]any{"Host": "cdn.example.com"}}},
		},
		"httpupgrade": {
			trojanBase + "type=httpupgrade&path=%2Fup&host=h.example.com",
			map[string]any{"network": "ws", "ws-opts": map[string]any{
				"path": "/up", "headers": map[string]any{"Host": "h.example.com"}, "v2ray-http-upgrade": true,
			}},
		},
		"grpc": {
			trojanBase + "type=grpc&serviceName=svc",
			map[string]any{"network": "grpc", "grpc-opts": map[string]any{"grpc-service-name": "svc"}},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := ProxyMapFromLink(tc.link)
			if err != nil {
				t.Fatalf("ProxyMapFromLink: %v", err)
			}
			wantFields(t, p, tc.want)
			wantFields(t, p, map[string]any{"type": "trojan", "sni": "sni.example.com"})
		})
	}
}

func TestTrojanProxy_Refuses(t *testing.T) {
	cases := map[string]string{
		"h2":          trojanBase + "type=h2&host=a.example.com",
		"tcp_header":  trojanBase + "headerType=http",
		"xhttp":       trojanBase + "type=xhttp",
		"kcp":         trojanBase + "type=kcp",
		"quic":        trojanBase + "type=quic",
		"h2_in_case":  trojanBase + "type=H2",
		"http_header": trojanBase + "type=tcp&headerType=http&host=a.example.com",
	}
	for name, link := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ProxyMapFromLink(link); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestBuildConfig_TrojanTransportsThroughMihomoParser(t *testing.T) {
	links := []string{
		trojanBase + "type=ws&path=%2Fws#WS",
		trojanBase + "type=grpc&serviceName=svc#GRPC",
		trojanBase + "type=httpupgrade&path=%2Fup#Upgrade",
	}
	cfg, err := BuildConfig(links, Inbound{MixedPort: 17890}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	for _, name := range []string{"WS", "GRPC", "Upgrade"} {
		if proxy, ok := cfg.Proxies[name]; !ok || proxy.Type().String() != "Trojan" {
			t.Fatalf("trojan proxy %q missing; have %v", name, cfg.Proxies)
		}
	}
	if _, err := BuildConfig([]string{trojanBase + "type=h2"}, Inbound{MixedPort: 17890}, Options{}, routing.Profile{}); err == nil {
		t.Fatal("BuildConfig accepted a Trojan link with an h2 transport")
	}
}
