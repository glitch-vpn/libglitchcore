package serverinfo

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestFromLink_VLESS(t *testing.T) {
	s := FromLink("vless://uuid@de1.example.com:443?type=ws&security=tls#Frankfurt%20%231", 3)
	if s.Index != 3 || s.Protocol != "vless" {
		t.Fatalf("index/protocol = %d/%q", s.Index, s.Protocol)
	}
	if s.Host != "de1.example.com" || s.Port != 443 {
		t.Fatalf("host/port = %q/%d", s.Host, s.Port)
	}
	if s.Name != "Frankfurt #1" {
		t.Fatalf("name = %q, want decoded fragment", s.Name)
	}
}

// v2rayN-style remarks encode spaces as '+', which url.Parse leaves as-is.
func TestFromLink_PlusInFragment(t *testing.T) {
	s := FromLink("vless://u@a.example.com:443#%F0%9F%87%A9%F0%9F%87%AA+%7C+Germany", 0)
	if s.Name != "🇩🇪 | Germany" {
		t.Fatalf("name = %q", s.Name)
	}
}

func TestFromLink_Trojan(t *testing.T) {
	s := FromLink("trojan://pass@nl.example.com:8443#NL", 0)
	if s.Protocol != "trojan" || s.Host != "nl.example.com" || s.Port != 8443 || s.Name != "NL" {
		t.Fatalf("got %+v", s)
	}
}

func TestFromLink_SSPlain(t *testing.T) {
	s := FromLink("ss://aes-128-gcm:secret@ss.example.com:8388#SS", 0)
	if s.Protocol != "ss" || s.Host != "ss.example.com" || s.Port != 8388 || s.Name != "SS" {
		t.Fatalf("got %+v", s)
	}
}

func TestFromLink_SSLegacyBase64(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret@legacy.example.com:8388"))
	s := FromLink("ss://"+payload+"#Legacy", 1)
	if s.Host != "legacy.example.com" || s.Port != 8388 {
		t.Fatalf("legacy ss host/port = %q/%d", s.Host, s.Port)
	}
	if s.Name != "Legacy" {
		t.Fatalf("name = %q", s.Name)
	}
}

func TestFromLink_Hysteria2(t *testing.T) {
	for _, scheme := range []string{"hysteria2", "hy2"} {
		s := FromLink(scheme+"://auth@hy.example.com:443?sni=x#HY", 0)
		if s.Protocol != "hysteria2" {
			t.Fatalf("%s: protocol = %q", scheme, s.Protocol)
		}
		if s.Host != "hy.example.com" || s.Port != 443 {
			t.Fatalf("%s: host/port = %q/%d", scheme, s.Host, s.Port)
		}
	}
}

const wgINI = `[Interface]
PrivateKey = aaaa
Address = 10.0.0.2/32

[Peer]
PublicKey = bbbb
Endpoint = wg.example.com:51820
AllowedIPs = 0.0.0.0/0
`

func TestFromLink_AwgLinkAndINI(t *testing.T) {
	link := "awg://" + base64.RawURLEncoding.EncodeToString([]byte(wgINI)) + "#My%20WG"
	s := FromLink(link, 2)
	if s.Protocol != "awg" || s.Name != "My WG" {
		t.Fatalf("awg link: %+v", s)
	}
	if s.Host != "wg.example.com" || s.Port != 51820 {
		t.Fatalf("awg endpoint = %q:%d", s.Host, s.Port)
	}

	ini := FromLink(wgINI, 0)
	if ini.Protocol != "awg" || ini.Host != "wg.example.com" || ini.Port != 51820 || ini.Name != "" {
		t.Fatalf("raw ini: %+v", ini)
	}
}

func TestFromLink_GarbageStillYieldsEntry(t *testing.T) {
	s := FromLink("definitely not a link", 5)
	if s.Index != 5 {
		t.Fatalf("index = %d", s.Index)
	}
}

func TestFromLinks_SkipsEmptiesKeepsOrder(t *testing.T) {
	servers := FromLinks([]string{
		"",
		"vless://u@a.example.com:443#A",
		"   ",
		"trojan://p@b.example.com:443#B",
	})
	if len(servers) != 2 {
		t.Fatalf("len = %d", len(servers))
	}
	if servers[0].Index != 0 || servers[0].Name != "A" {
		t.Fatalf("first: %+v", servers[0])
	}
	if servers[1].Index != 1 || servers[1].Name != "B" {
		t.Fatalf("second: %+v", servers[1])
	}
}

func TestSelectionJSON(t *testing.T) {
	servers := FromLinks([]string{"vless://u@a.example.com:443#A", "vless://u@b.example.com:443#B"})
	sel := Selection{Engine: "xray", Strategy: "leastping", Total: 2, Servers: servers}
	s := servers[1]
	sel.Selected = &s
	got, err := sel.JSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"engine":"xray"`, `"strategy":"leastping"`, `"total":2`,
		`"selected":{"index":1`, `"host":"b.example.com"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("JSON %s missing %s", got, want)
		}
	}
}

func TestSelectionJSON_NoSelected(t *testing.T) {
	sel := Selection{Engine: "xray", Strategy: "random", Total: 2}
	got, err := sel.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "selected") {
		t.Fatalf("nil Selected should be omitted: %s", got)
	}
}

func TestFromLink_TUIC(t *testing.T) {
	s := FromLink("tuic://6f4b7a3e-1c2d-4e5f-8a9b-0c1d2e3f4a5b:pw@tuic.example.com:8443?congestion_control=bbr#TUIC", 0)
	if s.Protocol != "tuic" || s.Host != "tuic.example.com" || s.Port != 8443 || s.Name != "TUIC" {
		t.Fatalf("got %+v", s)
	}
	if s := FromLink("tuic://token@tuic.example.com?sni=x", 0); s.Port != 443 {
		t.Fatalf("port = %d, want 443 for a link that names none", s.Port)
	}
}
