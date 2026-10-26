package xrayconfig

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func vlessEncryptionValue(t *testing.T) string {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
}

func vlessUserEncryption(t *testing.T, res *BuildResult) string {
	t.Helper()
	var settings struct {
		Vnext []struct {
			Users []struct {
				Encryption string `json:"encryption"`
			} `json:"users"`
		} `json:"vnext"`
	}
	if err := json.Unmarshal(*res.Config.OutboundConfigs[0].Settings, &settings); err != nil {
		t.Fatal(err)
	}
	return settings.Vnext[0].Users[0].Encryption
}

func TestVLESSEncryption_LinkValueReachesTheOutbound(t *testing.T) {
	resolveAs(t, nil)
	value := vlessEncryptionValue(t)
	res := buildLink(t, "vless://"+testVMessUUID+"@1.2.3.4:443?type=tcp&encryption="+value)
	if got := vlessUserEncryption(t, res); got != value {
		t.Errorf("outbound encryption = %q, want the link's", got)
	}
}

func TestVLESSEncryption_CountsAsTransportSecurity(t *testing.T) {
	resolveAs(t, nil)
	value := vlessEncryptionValue(t)
	for name, link := range map[string]string{
		"public_ip_ws":  "vless://" + testVMessUUID + "@1.2.3.4:443?type=ws&path=/x&encryption=" + value,
		"public_domain": "vless://" + testVMessUUID + "@vpn.example.org:443?encryption=" + value,
		"security_none": "vless://" + testVMessUUID + "@1.2.3.4:443?security=none&encryption=" + value,
		"public_ipv6":   "vless://" + testVMessUUID + "@[2001:4860:4860::8888]:443?encryption=" + value,
	} {
		t.Run(name, func(t *testing.T) { buildLink(t, link) })
	}
}

func TestVLESSEncryption_NoneOrAbsentStaysNone(t *testing.T) {
	resolveAs(t, nil)
	for _, query := range []string{"", "&encryption=none", "&encryption="} {
		res := buildLink(t, "vless://"+testVMessUUID+"@192.168.1.10:443?type=tcp"+query)
		if got := vlessUserEncryption(t, res); got != "none" {
			t.Errorf("query %q: outbound encryption = %q, want none", query, got)
		}
	}
	_, err := BuildConfig([]string{"vless://" + testVMessUUID + "@1.2.3.4:443?encryption=none"}, BalancerOptions{}, RoutingProfile{}, "none")
	if err == nil || !strings.Contains(err.Error(), "no TLS, REALITY or VLESS encryption") {
		t.Errorf("none on a public server without TLS: err = %v, want the no-TLS refusal", err)
	}
}

func TestVLESSEncryption_MalformedIsRefusedWithItsReason(t *testing.T) {
	resolveAs(t, nil)
	for name, value := range map[string]string{
		"unknown_scheme": "aes-128-gcm",
		"no_key":         "mlkem768x25519plus.native.0rtt",
		"bad_key":        "mlkem768x25519plus.native.0rtt." + strings.Repeat("A", 30),
	} {
		_, err := BuildConfig([]string{"vless://" + testVMessUUID + "@192.168.1.10:443?security=tls&encryption=" + value}, BalancerOptions{}, RoutingProfile{}, "none")
		if err == nil || !strings.Contains(err.Error(), "vless encryption:") {
			t.Errorf("%s: err = %v, want a vless encryption refusal", name, err)
		}
	}
}
