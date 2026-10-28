package xrayconfig

import (
	"strings"
	"testing"
)

const (
	testVMessUUID  = "6f4b7a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	testVLESSLink  = "vless://" + testVMessUUID + "@203.0.113.5:443?"
	testTrojanLink = "trojan://made-up-password@203.0.113.5:443?"
	testPin        = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// buildLink runs the link through xray's own config builder, which checks
// what the outbound and its stream settings say.
func buildLink(t *testing.T, link string) *BuildResult {
	t.Helper()
	res, err := BuildConfig([]string{link}, BalancerOptions{}, RoutingProfile{}, "none")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if _, err := res.Config.Build(); err != nil {
		t.Fatalf("xray rejects the config: %v", err)
	}
	return res
}

func TestStream_SkipVerificationIsRefusedNamingPCS(t *testing.T) {
	for name, link := range map[string]string{
		"vless_allowInsecure":  testVLESSLink + "security=tls&allowInsecure=1",
		"vless_insecure":       testVLESSLink + "security=tls&type=ws&insecure=true",
		"vless_allow_insecure": testVLESSLink + "security=tls&allow_insecure=1",
		"trojan_allowInsecure": testTrojanLink + "security=tls&allowInsecure=true",
		"trojan_implied_tls":   testTrojanLink + "allowInsecure=1",
		"trojan_security_none": testTrojanLink + "security=none&insecure=1",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := BuildConfig([]string{link}, BalancerOptions{}, RoutingProfile{}, "none")
			if err == nil || !strings.Contains(err.Error(), "pcs") {
				t.Fatalf("BuildConfig = %v, want a refusal naming pcs", err)
			}
		})
	}
}

func TestStream_SkipVerificationWithoutTLSIsHarmless(t *testing.T) {
	for name, link := range map[string]string{
		"vless": testVLESSLink + "security=none&allowInsecure=1",
		"vmess": vmessShared(t, map[string]any{"tls": "", "insecure": "1"}),
	} {
		t.Run(name, func(t *testing.T) {
			if tls := buildLink(t, link).Config.OutboundConfigs[0].StreamSetting.TLSSettings; tls != nil {
				t.Fatalf("a link without TLS must get no TLS settings: %+v", tls)
			}
		})
	}
}

func TestStream_PinnedCertificateReachesVLESSAndTrojan(t *testing.T) {
	for name, link := range map[string]string{
		"vless":  testVLESSLink + "security=tls&sni=a.example.com&pcs=" + testPin + "&vcn=cert.example.com",
		"trojan": testTrojanLink + "sni=a.example.com&pcs=" + testPin + "&vcn=cert.example.com",
	} {
		t.Run(name, func(t *testing.T) {
			tls := buildLink(t, link).Config.OutboundConfigs[0].StreamSetting.TLSSettings
			if tls.ServerName != "a.example.com" || tls.PinnedPeerCertSha256 != testPin || tls.VerifyPeerCertByName != "cert.example.com" {
				t.Fatalf("tls = %+v", tls)
			}
		})
	}
}

func TestStream_UnmappedTransportOrSecurityIsRefused(t *testing.T) {
	cases := map[string]string{
		"vless_kcp":         testVLESSLink + "type=kcp",
		"vless_h2":          testVLESSLink + "type=h2&security=tls",
		"vless_http":        testVLESSLink + "type=http&security=tls",
		"vless_quic":        testVLESSLink + "type=quic&security=tls",
		"vless_unknown":     testVLESSLink + "type=meek",
		"vless_tcp_header":  testVLESSLink + "type=tcp&headerType=http",
		"vless_security":    testVLESSLink + "security=xtls",
		"trojan_kcp":        testTrojanLink + "type=kcp",
		"trojan_grpc_typo":  testTrojanLink + "type=gprc",
		"trojan_tcp_header": testTrojanLink + "headerType=http",
	}
	for name, link := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := BuildConfig([]string{link}, BalancerOptions{}, RoutingProfile{}, "none")
			if err == nil || !strings.Contains(err.Error(), "is not supported") {
				t.Fatalf("BuildConfig = %v, want a refusal", err)
			}
		})
	}
}

func TestStream_EachMappedTransportReachesXray(t *testing.T) {
	for name, c := range map[string]struct{ link, network string }{
		"vless_raw":         {testVLESSLink + "type=raw", "tcp"},
		"vless_websocket":   {testVLESSLink + "type=websocket&path=/w", "websocket"},
		"vless_splithttp":   {testVLESSLink + "type=splithttp&security=tls", "xhttp"},
		"vless_grpc":        {testVLESSLink + "type=grpc&serviceName=svc", "grpc"},
		"vless_httpupgrade": {testVLESSLink + "type=httpupgrade&path=/up", "httpupgrade"},
		"trojan_tcp_plain":  {testTrojanLink + "type=tcp&headerType=none", "tcp"},
	} {
		t.Run(name, func(t *testing.T) {
			stream := buildLink(t, c.link).Config.OutboundConfigs[0].StreamSetting
			if stream.Network == nil || string(*stream.Network) != c.network {
				t.Fatalf("network = %v, want %s", stream.Network, c.network)
			}
		})
	}
}

func TestStream_SecurityIsTrimmedBeforeItIsRead(t *testing.T) {
	key := strings.Repeat("A", 43)
	for name, link := range map[string]string{
		"trojan": testTrojanLink + "security=%20reality&sni=a.example.com&pbk=" + key + "&sid=0123",
		"vless":  testVLESSLink + "security=%20reality&sni=a.example.com&pbk=" + key + "&sid=0123",
	} {
		t.Run(name, func(t *testing.T) {
			stream := buildLink(t, link).Config.OutboundConfigs[0].StreamSetting
			if stream.REALITYSettings == nil || stream.TLSSettings != nil {
				t.Fatalf("security with a space must be REALITY: %+v", stream)
			}
		})
	}
	if _, err := BuildConfig([]string{vmessShared(t, map[string]any{"tls": " reality"})}, BalancerOptions{}, RoutingProfile{}, "none"); err == nil {
		t.Fatal("vmess reality accepted")
	}
}
