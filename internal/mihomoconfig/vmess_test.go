package mihomoconfig

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

func vmessShared(t *testing.T, fields map[string]any) string {
	t.Helper()
	base := map[string]any{"v": "2", "ps": "VM", "add": "203.0.113.5", "port": "443", "id": testUUID, "aid": "0"}
	for k, v := range fields {
		base[k] = v
	}
	b, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func TestVmessProxy(t *testing.T) {
	cases := []struct {
		name string
		link string
		want map[string]any
	}{
		{
			name: "shared_json_ws_tls_early_data",
			link: vmessShared(t, map[string]any{
				"scy": "aes-128-gcm", "net": "ws", "host": "cdn.example.com", "path": "/vm?ed=2048",
				"tls": "tls", "sni": "sni.example.com", "alpn": "h2,http/1.1", "fp": "chrome", "insecure": "1",
			}),
			want: map[string]any{
				"type": "vmess", "server": "203.0.113.5", "port": 443, "uuid": testUUID, "alterId": 0,
				"cipher": "aes-128-gcm", "udp": true, "xudp": true, "network": "ws",
				"ws-opts": map[string]any{
					"path": "/vm", "headers": map[string]any{"Host": "cdn.example.com"},
					"max-early-data": 2048, "early-data-header-name": "Sec-WebSocket-Protocol",
				},
				"tls": true, "servername": "sni.example.com", "alpn": []string{"h2", "http/1.1"},
				"client-fingerprint": "chrome", "skip-cert-verify": true,
			},
		},
		{
			name: "shared_json_legacy_alter_id",
			link: vmessShared(t, map[string]any{"aid": "64", "scy": "aes-128-cfb"}),
			want: map[string]any{"alterId": 64, "cipher": "aes-128-cfb", "network": "tcp", "tls": nil},
		},
		{
			name: "shared_json_tcp_http_header",
			link: vmessShared(t, map[string]any{"net": "tcp", "type": "http", "host": "a.example.com,b.example.com", "path": "/x"}),
			want: map[string]any{
				"network":   "http",
				"http-opts": map[string]any{"path": []string{"/x"}, "headers": map[string]any{"Host": []string{"a.example.com", "b.example.com"}}},
			},
		},
		{
			name: "shared_json_h2",
			link: vmessShared(t, map[string]any{"net": "h2", "host": "a.example.com", "tls": "tls"}),
			want: map[string]any{"network": "h2", "h2-opts": map[string]any{"path": "/", "host": []string{"a.example.com"}}, "tls": true},
		},
		{
			name: "uri_grpc_pinned",
			link: "vmess://" + testUUID + "@203.0.113.5:8443?type=grpc&serviceName=svc&security=tls&encryption=none&pcs=" + testCertPin + "&packetEncoding=packet#URI",
			want: map[string]any{
				"network": "grpc", "grpc-opts": map[string]any{"grpc-service-name": "svc"}, "cipher": "none",
				"fingerprint": testCertPin, "packet-addr": true, "xudp": nil, "port": 8443,
			},
		},
		{
			name: "uri_httpupgrade_fast_open",
			link: "vmess://" + testUUID + "@203.0.113.5:80?type=httpupgrade&path=%2Fup%3Fed%3D2048&host=h.example.com",
			want: map[string]any{
				"network": "ws",
				"ws-opts": map[string]any{
					"path": "/up", "headers": map[string]any{"Host": "h.example.com"},
					"v2ray-http-upgrade": true, "v2ray-http-upgrade-fast-open": true,
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ProxyMapFromLink(tc.link)
			if err != nil {
				t.Fatalf("ProxyMapFromLink: %v", err)
			}
			wantFields(t, p, tc.want)
		})
	}
}

func TestVmessProxy_Refuses(t *testing.T) {
	cases := map[string]string{
		"unknown_cipher": vmessShared(t, map[string]any{"scy": "aes-256-cfb"}),
		"kcp":            vmessShared(t, map[string]any{"net": "kcp"}),
		"quic":           vmessShared(t, map[string]any{"net": "quic"}),
		"xhttp":          vmessShared(t, map[string]any{"net": "xhttp"}),
		"tcp_header":     vmessShared(t, map[string]any{"net": "tcp", "type": "srtp"}),
		"reality":        vmessShared(t, map[string]any{"tls": "reality"}),
		"no_uuid":        vmessShared(t, map[string]any{"id": ""}),
		"bad_port":       vmessShared(t, map[string]any{"port": "x"}),
		"bad_early_data": vmessShared(t, map[string]any{"net": "ws", "path": "/?ed=lots"}),
		"not_json":       "vmess://" + base64.StdEncoding.EncodeToString([]byte("nope")),
	}
	for name, link := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ProxyMapFromLink(link); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestBuildConfig_VmessThroughMihomoParser(t *testing.T) {
	links := []string{
		vmessShared(t, map[string]any{"ps": "Shared, JSON", "net": "ws", "path": "/vm?ed=2048", "tls": "tls", "sni": "a.example.com"}),
		"vmess://" + testUUID + "@203.0.113.6:443?type=grpc&serviceName=svc&security=tls&sni=b.example.com#URI%20form",
		vmessShared(t, map[string]any{"ps": "Legacy", "aid": "1", "net": "h2", "tls": "tls"}),
	}
	cfg, err := BuildConfig(links, Inbound{MixedPort: 17890}, Options{Fingerprint: "safari"}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	// The JSON form names its server in ps; a comma would split rule lines.
	for _, name := range []string{"Shared  JSON", "URI form", "Legacy"} {
		if proxy, ok := cfg.Proxies[name]; !ok || proxy.Type().String() != "Vmess" {
			t.Fatalf("vmess proxy %q missing; have %v", name, cfg.Proxies)
		}
	}
	if got := ProxyNames(links); got[0] != "Shared  JSON" || got[1] != "URI form" {
		t.Fatalf("ProxyNames = %v", got)
	}
	if got := ProxyNames([]string{vmessShared(t, map[string]any{"ps": "C++ team"})}); got[0] != "C++ team" {
		t.Fatalf("a '+' in ps is a plus: ProxyNames = %v", got)
	}
	p, err := ProxyMapFromLink(links[0])
	if err != nil {
		t.Fatal(err)
	}
	applyProxyFingerprint(p, "safari")
	if p["client-fingerprint"] != "safari" {
		t.Fatalf("the fingerprint option must reach a vmess proxy, got %v", p["client-fingerprint"])
	}
}
