package mihomoconfig

import (
	"reflect"
	"strings"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

const testUUID = "6f4b7a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b"

// A made-up hex SHA-256, the shape v2rayN's pcs and mihomo's fingerprint take.
const testCertPin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func wantFields(t *testing.T, p map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if v == nil {
			if got, ok := p[k]; ok {
				t.Errorf("%s = %#v, want unset", k, got)
			}
			continue
		}
		if !reflect.DeepEqual(p[k], v) {
			t.Errorf("%s = %#v, want %#v", k, p[k], v)
		}
	}
}

func TestTuicProxy(t *testing.T) {
	cases := []struct {
		name string
		link string
		want map[string]any
	}{
		{
			name: "v5_every_parameter",
			link: "tuic://" + testUUID + ":s3cret@tuic.example.com:8443?sni=sni.example.com&alpn=h3,%20h3-29&congestion_control=BBR&udp_relay_mode=quic&allow_insecure=1#TUIC",
			want: map[string]any{
				"type": "tuic", "server": "tuic.example.com", "port": 8443, "udp": true,
				"uuid": testUUID, "password": "s3cret", "token": nil,
				"sni": "sni.example.com", "alpn": []string{"h3", "h3-29"},
				"congestion-controller": "bbr", "udp-relay-mode": "quic", "skip-cert-verify": true,
			},
		},
		{
			name: "v4_token_default_port",
			link: "tuic://tok3n@203.0.113.7",
			want: map[string]any{"server": "203.0.113.7", "port": 443, "token": "tok3n", "uuid": nil, "password": nil},
		},
		{
			name: "sni_off_and_certificate_checks",
			link: "tuic://" + testUUID + ":pw@tuic.example.com:443?disable_sni=1&pcs=" + testCertPin + "&vcn=cert.example.com&ech=AEX%2BDQBBAAAgACA%3D",
			want: map[string]any{
				"disable-sni": true, "fingerprint": testCertPin, "name-cert-verify": "cert.example.com",
				"ech-opts": map[string]any{"enable": true, "config": "AEX+DQBBAAAgACA="},
			},
		},
		{
			name: "insecure_spellings",
			link: "tuic://" + testUUID + ":pw@h.example.com:443?insecure=true&security=tls&fp=chrome",
			want: map[string]any{"skip-cert-verify": true, "client-fingerprint": nil},
		},
		{
			name: "ech_switch",
			link: "tuic://" + testUUID + ":pw@h.example.com:443?ech=1&hpkp=" + testCertPin,
			want: map[string]any{"ech-opts": map[string]any{"enable": true}, "fingerprint": testCertPin},
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

func TestTuicProxy_Refuses(t *testing.T) {
	cases := map[string]string{
		"no_uuid":            "tuic://@h.example.com:443",
		"no_host":            "tuic://" + testUUID + ":pw@:443",
		"bad_port":           "tuic://" + testUUID + ":pw@h.example.com:70000",
		"reality":            "tuic://" + testUUID + ":pw@h.example.com:443?security=reality&pbk=x",
		"congestion_control": "tuic://" + testUUID + ":pw@h.example.com:443?congestion_control=vegas",
		"udp_relay_mode":     "tuic://" + testUUID + ":pw@h.example.com:443?udp_relay_mode=stream",
		"two_pins":           "tuic://" + testUUID + ":pw@h.example.com:443?pcs=aa,bb",
		"ech_query_form":     "tuic://" + testUUID + ":pw@h.example.com:443?ech=example.com%2Budp%3A%2F%2F1.1.1.1",
	}
	for name, link := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ProxyMapFromLink(link); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestTuicProxy_ErrorKeepsCredentialsOut(t *testing.T) {
	for name, link := range map[string]string{
		"bad_port":        "tuic://" + testUUID + ":hunter2@h.example.com:x1",
		"hash_in_secret":  "tuic://" + testUUID + ":hunter2#rest@h.example.com:443",
		"slash_in_secret": "tuic://" + testUUID + ":hunter2/rest@h.example.com:443",
		"no_host":         "tuic://" + testUUID + ":hunter2",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ProxyMapFromLink(link)
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), testUUID) {
				t.Fatalf("error carries the link's credentials: %v", err)
			}
		})
	}
}

func TestBuildConfig_TuicThroughMihomoParser(t *testing.T) {
	links := []string{
		"tuic://" + testUUID + ":pw@tuic.example.com:443?sni=tuic.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native#v5",
		"tuic://tok3n@tuic.example.com:443?pcs=" + testCertPin + "#v4",
	}
	cfg, err := BuildConfig(links, Inbound{MixedPort: 17890}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	for _, name := range []string{"v5", "v4"} {
		proxy, ok := cfg.Proxies[name]
		if !ok {
			t.Fatalf("proxy %q missing", name)
		}
		if got := proxy.Type().String(); got != "Tuic" {
			t.Fatalf("proxy %q type = %s", name, got)
		}
	}
}
