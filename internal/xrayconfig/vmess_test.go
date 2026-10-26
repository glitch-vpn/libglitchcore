package xrayconfig

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func vmessShared(t *testing.T, fields map[string]any) string {
	t.Helper()
	base := map[string]any{"v": "2", "ps": "VM", "add": "203.0.113.5", "port": "443", "id": testVMessUUID, "aid": "0"}
	for k, v := range fields {
		base[k] = v
	}
	b, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func TestVMess_SharedJSONOverWebSocketTLS(t *testing.T) {
	res := buildLink(t, vmessShared(t, map[string]any{
		"scy": "aes-128-gcm", "net": "ws", "host": "cdn.example.com", "path": "/vm?ed=2048",
		"tls": "tls", "sni": "sni.example.com", "alpn": "h2,http/1.1", "fp": "chrome",
	}))
	ob := res.Config.OutboundConfigs[0]
	if ob.Protocol != "vmess" || ob.Tag != OutboundTag || res.Servers[0] != "203.0.113.5" {
		t.Fatalf("outbound = %s/%s, servers %v", ob.Protocol, ob.Tag, res.Servers)
	}
	settings := string(*ob.Settings)
	if !strings.Contains(settings, `"id":"`+testVMessUUID+`"`) || !strings.Contains(settings, `"security":"aes-128-gcm"`) {
		t.Fatalf("settings = %s", settings)
	}
	stream := ob.StreamSetting
	if string(*stream.Network) != "websocket" || stream.WSSettings.Path != "/vm?ed=2048" || stream.WSSettings.Host != "cdn.example.com" {
		t.Fatalf("ws = %+v", stream.WSSettings)
	}
	tls := stream.TLSSettings
	if stream.Security != "tls" || tls.ServerName != "sni.example.com" || tls.Fingerprint != "chrome" ||
		tls.ALPN == nil || len(*tls.ALPN) != 2 {
		t.Fatalf("tls = %+v", tls)
	}
}

func TestVMess_URIFormWithCertificateChecks(t *testing.T) {
	res := buildLink(t, "vmess://"+testVMessUUID+"@203.0.113.5:8443?type=grpc&serviceName=svc&security=tls&sni=a.example.com&pcs="+testPin+"&vcn=cert.example.com&ech=AEX%2BDQBBAAAgACA%3D#URI")
	stream := res.Config.OutboundConfigs[0].StreamSetting
	if string(*stream.Network) != "grpc" || stream.GRPCSettings.ServiceName != "svc" {
		t.Fatalf("grpc = %+v", stream.GRPCSettings)
	}
	tls := stream.TLSSettings
	if tls.PinnedPeerCertSha256 != testPin || tls.VerifyPeerCertByName != "cert.example.com" || tls.ECHConfigList != "AEX+DQBBAAAgACA=" {
		t.Fatalf("tls = %+v", tls)
	}
}

func TestVMess_PlainTCPWithoutTLS(t *testing.T) {
	res := buildLink(t, vmessShared(t, map[string]any{"net": "tcp", "type": "none", "tls": ""}))
	stream := res.Config.OutboundConfigs[0].StreamSetting
	if stream.Security != "" || string(*stream.Network) != "tcp" {
		t.Fatalf("stream = %+v", stream)
	}
	if !strings.Contains(string(*res.Config.OutboundConfigs[0].Settings), `"security":"auto"`) {
		t.Fatalf("a link naming no cipher must ask for auto: %s", *res.Config.OutboundConfigs[0].Settings)
	}
}

func TestVMess_Refuses(t *testing.T) {
	cases := map[string]map[string]any{
		"legacy_alter_id": {"aid": "64"},
		"unknown_cipher":  {"scy": "aes-256-cfb"},
		"cipher_none":     {"scy": "none"},
		"cipher_zero":     {"scy": "zero"},
		"h2":              {"net": "h2"},
		"quic":            {"net": "quic"},
		"kcp":             {"net": "kcp"},
		"tcp_http_header": {"net": "tcp", "type": "http"},
		"reality":         {"tls": "reality"},
		"no_uuid":         {"id": ""},
		"skip_verify":     {"tls": "tls", "insecure": "1"},
	}
	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildConfig([]string{vmessShared(t, fields)}, BalancerOptions{}, RoutingProfile{}, "none"); err == nil {
				t.Fatal("want an error")
			}
		})
	}
	for name, query := range map[string]string{"ech_switch": "ech=1", "allow_insecure": "allowInsecure=true"} {
		t.Run(name, func(t *testing.T) {
			link := "vmess://" + testVMessUUID + "@203.0.113.5:443?security=tls&" + query
			if _, err := BuildConfig([]string{link}, BalancerOptions{}, RoutingProfile{}, "none"); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

func TestVMess_FingerprintOptionReachesIt(t *testing.T) {
	res := buildLink(t, vmessShared(t, map[string]any{"tls": "tls", "fp": "chrome"}))
	ApplyFingerprint(res.Config, res.OutboundTags, "firefox")
	if got := res.Config.OutboundConfigs[0].StreamSetting.TLSSettings.Fingerprint; got != "firefox" {
		t.Fatalf("fingerprint = %q", got)
	}
}
