package mihomoconfig

import (
	"crypto/mlkem"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/transport/vless/encryption"
)

func TestVLESSEncryption_LinkValueReachesTheProxyAndMihomoRunsIt(t *testing.T) {
	private, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	value := "mlkem768x25519plus.xorpub.1rtt." + base64.RawURLEncoding.EncodeToString(private.EncapsulationKey().Bytes())
	p, err := ProxyMapFromLink("vless://" + testUUID + "@1.2.3.4:443?type=tcp&encryption=" + value)
	if err != nil {
		t.Fatalf("ProxyMapFromLink: %v", err)
	}
	if p["encryption"] != value {
		t.Errorf("encryption = %v, want the link's", p["encryption"])
	}
	if _, err := encryption.NewClient(p["encryption"].(string)); err != nil {
		t.Errorf("mihomo refuses the value the core carried: %v", err)
	}
}

func TestVLESSEncryption_NoneOrAbsentSetsNothing(t *testing.T) {
	for _, query := range []string{"", "&encryption=none", "&encryption="} {
		p, err := ProxyMapFromLink("vless://" + testUUID + "@1.2.3.4:443?type=tcp" + query)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p["encryption"]; ok {
			t.Errorf("query %q: encryption set to %v", query, p["encryption"])
		}
	}
}

func TestVLESSEncryption_MalformedIsRefusedWithItsReason(t *testing.T) {
	_, err := ProxyMapFromLink("vless://" + testUUID + "@1.2.3.4:443?encryption=mlkem768x25519plus.native.0rtt." + strings.Repeat("A", 30))
	if err == nil || !strings.Contains(err.Error(), "vless encryption:") {
		t.Errorf("err = %v, want a vless encryption refusal", err)
	}
}
