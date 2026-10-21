package mihomoconfig

import (
	"strings"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

func TestAnytlsProxy(t *testing.T) {
	cases := []struct {
		name string
		link string
		want map[string]any
	}{
		{
			name: "anytls_go_spec_default_port",
			link: "anytls://letmein@example.com/?sni=real.example.com",
			want: map[string]any{
				"type": "anytls", "server": "example.com", "port": 443, "password": "letmein", "udp": true,
				"sni": "real.example.com", "skip-cert-verify": nil,
			},
		},
		{
			name: "anytls_go_spec_ipv6",
			link: "anytls://" + testUUID + "@[2001:db8::615]:8964/?insecure=1",
			want: map[string]any{"server": "2001:db8::615", "port": 8964, "password": testUUID, "skip-cert-verify": true},
		},
		{
			name: "v2rayN_tls_keys",
			link: "anytls://p%40ss@203.0.113.9:443?security=tls&type=tcp&sni=sni.example.com&fp=firefox&alpn=h2,http/1.1&pcs=" + testCertPin + "#AnyTLS",
			want: map[string]any{
				"password": "p@ss", "sni": "sni.example.com", "client-fingerprint": "firefox",
				"alpn": []string{"h2", "http/1.1"}, "fingerprint": testCertPin,
			},
		},
		{
			name: "hiddify_peer_and_colon_password",
			link: "anytls://user:pass@h.example.com:443?peer=peer.example.com&allowInsecure=true",
			want: map[string]any{"password": "user:pass", "sni": "peer.example.com", "skip-cert-verify": true},
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

func TestAnytlsProxy_Refuses(t *testing.T) {
	cases := map[string]string{
		"no_password": "anytls://h.example.com:443",
		"no_host":     "anytls://pw@:443",
		"bad_port":    "anytls://pw@h.example.com:0",
		"reality":     "anytls://pw@h.example.com:443?security=reality&pbk=x&sid=1",
		"no_tls":      "anytls://pw@h.example.com:443?security=none",
		"transport":   "anytls://pw@h.example.com:443?type=ws&path=%2F",
		"ech_query":   "anytls://pw@h.example.com:443?ech=example.com%2Budp%3A%2F%2F1.1.1.1",
	}
	for name, link := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ProxyMapFromLink(link)
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), "pw@") {
				t.Fatalf("error carries the link: %v", err)
			}
		})
	}
}

func TestAnytlsProxy_ErrorKeepsCredentialsOut(t *testing.T) {
	for name, link := range map[string]string{
		"bad_port":        "anytls://hunter2@h.example.com:x1",
		"hash_in_secret":  "anytls://user:hunter2#rest@h.example.com:443",
		"slash_in_secret": "anytls://user:hunter2/rest@h.example.com:443",
		"no_host":         "anytls://user:hunter2",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ProxyMapFromLink(link)
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("error carries the link's password: %v", err)
			}
		})
	}
}

func TestBuildConfig_AnytlsThroughMihomoParser(t *testing.T) {
	link := "anytls://pw@anytls.example.com:443?sni=anytls.example.com&fp=chrome#a"
	cfg, err := BuildConfig([]string{link}, Inbound{MixedPort: 17890}, Options{Fingerprint: "safari"}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if proxy, ok := cfg.Proxies["a"]; !ok || proxy.Type().String() != "AnyTLS" {
		t.Fatalf("anytls proxy missing; have %v", cfg.Proxies)
	}
	p, err := ProxyMapFromLink(link)
	if err != nil {
		t.Fatal(err)
	}
	applyProxyFingerprint(p, "safari")
	if p["client-fingerprint"] != "safari" {
		t.Fatalf("the fingerprint option must reach an anytls proxy, got %v", p["client-fingerprint"])
	}
}
