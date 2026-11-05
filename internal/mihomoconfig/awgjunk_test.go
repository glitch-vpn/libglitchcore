package mihomoconfig

import "testing"

func TestAmneziaJunkCount_CappedAtDocumentedMaximum(t *testing.T) {
	for _, extra := range []string{"", "RekeyTimeout = 5\n"} {
		if _, err := ProxyMapFromLink(awgINIWith(extra + "Jc = 128\n")); err != nil {
			t.Errorf("Jc = 128: %v", err)
		}
		for _, bad := range []string{"129", "100000", "-1"} {
			if _, err := ProxyMapFromLink(awgINIWith(extra + "Jc = " + bad + "\n")); err == nil {
				t.Errorf("Jc = %s: want an error", bad)
			}
		}
	}
	link := "wg://203.0.113.7:51820?pk=" + wgPrivateKey + "&pub=" + wgPublicKey + "&jc=100000"
	if _, err := ProxyMapFromLink(link); err == nil {
		t.Error("link jc=100000: want an error")
	}
}
