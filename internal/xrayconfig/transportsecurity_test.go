package xrayconfig

import (
	"context"
	"net"
	"strings"
	"testing"
)

// resolveAs replaces the DNS lookup behind a link's dial address; a name
// missing from answers does not resolve.
func resolveAs(t *testing.T, answers map[string]string) {
	t.Helper()
	previous := lookupIPv4
	lookupIPv4 = func(_ context.Context, host string) ([]net.IP, error) {
		if ip, ok := answers[host]; ok {
			return []net.IP{net.ParseIP(ip)}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	t.Cleanup(func() { lookupIPv4 = previous })
}

func TestTransportSecurity_VLESSWithoutTLSToAPublicServerIsRefused(t *testing.T) {
	resolveAs(t, nil)
	for name, link := range map[string]string{
		"public_ip":     "vless://" + testVMessUUID + "@1.2.3.4:443?type=tcp&security=none",
		"no_security":   "vless://" + testVMessUUID + "@1.2.3.4:443?type=ws&path=/x",
		"public_domain": "vless://" + testVMessUUID + "@vpn.example.org:443?type=grpc&serviceName=s",
		"public_ipv6":   "vless://" + testVMessUUID + "@[2001:4860:4860::8888]:443",
	} {
		_, err := BuildConfig([]string{link}, BalancerOptions{}, RoutingProfile{}, "none")
		if err == nil || !strings.Contains(err.Error(), "no TLS or REALITY") {
			t.Errorf("%s: err = %v, want the no-TLS refusal", name, err)
		}
	}
}

func TestTransportSecurity_PrivateServersAndSecuredLinksPass(t *testing.T) {
	resolveAs(t, nil)
	for name, link := range map[string]string{
		"lan_ip":        "vless://" + testVMessUUID + "@192.168.1.10:443",
		"loopback":      "vless://" + testVMessUUID + "@127.0.0.1:443",
		"cgnat":         "vless://" + testVMessUUID + "@100.64.0.9:443",
		"ula_ipv6":      "vless://" + testVMessUUID + "@[fd00::1]:443",
		"localhost":     "vless://" + testVMessUUID + "@localhost:443",
		"tls_public":    "vless://" + testVMessUUID + "@1.2.3.4:443?security=tls&sni=a.example.com",
		"reality":       "vless://" + testVMessUUID + "@1.2.3.4:443?security=reality&sni=a.example.com&pbk=" + strings.Repeat("A", 43) + "&sid=0123",
		"trojan_public": "trojan://secret@1.2.3.4:443?sni=a.example.com",
	} {
		t.Run(name, func(t *testing.T) { buildLink(t, link) })
	}
}

func TestTransportSecurity_DecidedOnTheAddressXrayGets(t *testing.T) {
	resolveAs(t, map[string]string{
		"lan.example.org": "192.168.1.10",
		"cdn.example.org": "1.2.3.4",
	})
	if res := buildLink(t, "vless://"+testVMessUUID+"@lan.example.org:443"); res.DialIPv4s[0] != "192.168.1.10" {
		t.Fatalf("dial address = %v", res.DialIPv4s)
	}
	_, err := BuildConfig([]string{"vless://" + testVMessUUID + "@localhost:443"}, BalancerOptions{}, RoutingProfile{}, "none")
	if err != nil {
		t.Fatalf("a private name that resolves to no address: %v", err)
	}
	_, err = BuildConfig([]string{"vless://" + testVMessUUID + "@cdn.example.org:443"}, BalancerOptions{}, RoutingProfile{}, "none")
	if err == nil || !strings.Contains(err.Error(), "no TLS or REALITY") {
		t.Fatalf("a name that resolves to a public address: %v", err)
	}
}

func TestTransportSecurity_VMessWithoutTLSIsNotRefused(t *testing.T) {
	buildLink(t, vmessShared(t, map[string]any{"add": "1.2.3.4", "net": "tcp", "tls": ""}))
}

func TestShadowsocks_MethodsXrayDroppedAreRefused(t *testing.T) {
	for _, method := range []string{"none", "plain", "rc4-md5", "aes-256-cfb", "chacha20"} {
		_, err := BuildConfig([]string{"ss://" + method + ":pw@1.2.3.4:8388"}, BalancerOptions{}, RoutingProfile{}, "none")
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Errorf("%s: err = %v, want the unsupported-method refusal", method, err)
		}
	}
}

func TestShadowsocks_SupportedMethodsBuild(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "AES-256-GCM", "chacha20-ietf-poly1305", "xchacha20-poly1305"} {
		t.Run(method, func(t *testing.T) { buildLink(t, "ss://"+method+":pw@1.2.3.4:8388") })
	}
	buildLink(t, "ss://2022-blake3-aes-128-gcm:MDEyMzQ1Njc4OWFiY2RlZg==@1.2.3.4:8388")
}
