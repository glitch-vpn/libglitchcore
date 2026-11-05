package mihomoconfig

import (
	"strings"
	"testing"
)

func awgINIWith(interfaceLines string) string {
	return "[Interface]\nPrivateKey = " + wgPrivateKey + "\nAddress = 10.0.0.2/32\n" + interfaceLines +
		"\n[Peer]\nPublicKey = " + wgPublicKey + "\nEndpoint = 203.0.113.7:51820\n"
}

// Each of these made amneziawg-go panic while mihomo built the outbound; the
// config is refused instead, whichever way it arrives.
func TestAmneziaChains_MalformedRefusedNotPanicking(t *testing.T) {
	inis := map[string]string{
		"j1 with a +":          awgINIWith("J1 = <r+10>\n"),
		"j1 without a tag":     awgINIWith("J1 = <1>\n"),
		"i1 without a tag":     awgINIWith("I1 = <1>\n"),
		"i1 with a number":     awgINIWith("I1 = 30\n"),
		"i1 negative size":     awgINIWith("I1 = <r -5>\n"),
		"i1 oversize":          awgINIWith("I1 = <r 5000>\n"),
		"i3 unclosed":          awgINIWith("I3 = <b 0xf6\n"),
		"i2 unknown tag":       awgINIWith("I2 = <zz 4>\n"),
		"3.x i1 odd hex":       awgINIWith("RekeyTimeout = 5\nI1 = <b 0xf6a>\n"),
		"3.x i1 unknown tag":   awgINIWith("RekeyTimeout = 5\nI1 = <c>\n"),
		"3.x i1 negative size": awgINIWith("RekeyTimeout = 5\nI1 = <rc -1>\n"),
		"3.x i1 empty":         awgINIWith("RekeyTimeout = 5\nI1 = abc\n"),
		"3.x i5 bad size":      awgINIWith("RekeyTimeout = 5\nI5 = <dz x>\n"),
	}
	for name, ini := range inis {
		t.Run(name, func(t *testing.T) {
			if _, err := ProxyMapFromLink(ini); err == nil {
				t.Errorf("want an error for the chain")
			}
		})
	}

	links := []string{
		"wg://203.0.113.7:51820?pk=" + wgPrivateKey + "&pub=" + wgPublicKey + "&j1=<1>",
		"wg://203.0.113.7:51820?pk=" + wgPrivateKey + "&pub=" + wgPublicKey + "&i1=<1>",
	}
	for _, link := range links {
		if _, err := ProxyMapFromLink(link); err == nil {
			t.Errorf("%s: want an error", link[strings.Index(link, "&pub"):])
		}
	}
}

func TestAmneziaChains_LinkPlusIsSpaceInJunkChain(t *testing.T) {
	link := "wg://203.0.113.7:51820?pk=" + wgPrivateKey + "&pub=" + wgPublicKey + "&j1=<r+10>"
	p, err := ProxyMapFromLink(link)
	if err != nil {
		t.Fatalf("ProxyMapFromLink: %v", err)
	}
	if opt, _ := p["amnezia-wg-option"].(map[string]any); opt["j1"] != "<r 10>" {
		t.Errorf("j1 = %v, want <r 10>", opt["j1"])
	}
}

func TestAmneziaChains_ValidStillPass(t *testing.T) {
	inis := map[string]string{
		"1.5":   awgINIWith("Jc = 4\nI1 = <b 0xf6ab3267fa><c><b 0xf6ab><t><r 10>\nI2 = <rc 8><rd 4>\nJ1 = <r 16>\nJ2 = <b 0x00>\nJ3 = <wt 100>\n"),
		"3.x":   awgINIWith("Jc = 4\nRekeyTimeout = 5\nI1 = <b 0xc30000000108><rc 8><t><d><ds><dz 2><r 10>\nI2 = <rd 4>\n"),
		"quote": awgINIWith("I1 = <b 0xf6ab>\n"),
	}
	for name, ini := range inis {
		t.Run(name, func(t *testing.T) {
			if _, err := ProxyMapFromLink(ini); err != nil {
				t.Errorf("ProxyMapFromLink: %v", err)
			}
		})
	}
}
