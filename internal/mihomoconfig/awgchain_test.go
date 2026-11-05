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

// Each of these is accepted by the config reader and fails only when the
// device is built, at the first dial.
func TestAmneziaChains_RefusedAtBuildWhatTheDeviceRefuses(t *testing.T) {
	long := "<b 0x" + strings.Repeat("ab", 40000) + ">"
	bad := map[string]string{
		"3.x uppercase 0X":           awgINIWith("RekeyTimeout = 5\nI1 = <b 0Xf6ab>\n"),
		"3.x empty bytes":            awgINIWith("RekeyTimeout = 5\nI1 = <b 0x>\n"),
		"3.x chain past the line":    awgINIWith("RekeyTimeout = 5\nI1 = " + long + "\n"),
		"legacy chain past the line": awgINIWith("I1 = " + long + "\n"),
		"i2 without i1":              awgINIWith("I2 = <r 4>\n"),
		"i1 and i3 without i2":       awgINIWith("I1 = <r 4>\nI3 = <r 4>\n"),
		"j2 without j1":              awgINIWith("J2 = <r 4>\n"),
		"j3 with j1 only":            awgINIWith("J1 = <r 4>\nJ3 = <r 4>\n"),
		"h1 dash":                    awgINIWith("H1 = -\n"),
		"h1 open range":              awgINIWith("H1 = 1-\n"),
		"h2 reversed":                awgINIWith("H2 = 5-3\n"),
		"h3 letter":                  awgINIWith("H3 = a\n"),
		"h4 past 32 bits":            awgINIWith("H4 = 4294967296\n"),
		"h1 three parts":             awgINIWith("H1 = 1-2-3\n"),
		"3.x h1 three parts":         awgINIWith("RekeyTimeout = 5\nH1 = 1-2-3\n"),
	}
	for name, ini := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := ProxyMapFromLink(ini); err == nil {
				t.Error("want an error")
			}
		})
	}
	good := map[string]string{
		"legacy uppercase 0X":    awgINIWith("I1 = <b 0Xf6ab>\n"),
		"legacy empty bytes":     awgINIWith("I1 = <b 0x>\n"),
		"consecutive i and j":    awgINIWith("I1 = <r 4>\nI2 = <r 4>\nJ1 = <r 4>\nJ2 = <r 4>\n"),
		"3.x i2 without i1":      awgINIWith("RekeyTimeout = 5\nI2 = <r 4>\n"),
		"headers, single, range": awgINIWith("H1 = 7\nH2 = 100-200\n"),
	}
	for name, ini := range good {
		t.Run(name, func(t *testing.T) {
			if _, err := ProxyMapFromLink(ini); err != nil {
				t.Errorf("ProxyMapFromLink: %v", err)
			}
		})
	}
}
