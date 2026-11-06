package pinger

import (
	"errors"
	"testing"
)

func TestNewDialerRefusesALinkTheEngineChoiceCannotCarry(t *testing.T) {
	if fallback == nil || !hasLinkEngine("xray") {
		t.Skip("needs xray and the mihomo fallback")
	}
	cases := []struct {
		name, pinned, link string
		want               error
	}{
		{"unknown scheme", "", "nonsense://whatever", errUnsupportedLink},
		{"mihomo-only link pinned to xray", "xray", "hysteria2://auth@127.0.0.1:1#h", errNotCarried},
		{"xray-only link pinned to mihomo", "mihomo", "http://127.0.0.1:1", errNotCarried},
		{"engine nobody has", "nonesuch", "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@127.0.0.1:1?type=tcp&security=tls", errNotCarried},
	}
	for _, c := range cases {
		d, err := NewDialer(c.pinned, c.link)
		if d != nil {
			d.Release()
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestNewDialerCarriesALinkXrayRefusesOnMihomo(t *testing.T) {
	if fallback == nil || fallback.engine != "mihomo" || !hasLinkEngine("xray") {
		t.Skip("needs xray and the mihomo fallback")
	}
	legacy := vmessLink(1, `"aid":"2","net":"tcp","type":"none","tls":""`)

	d, err := NewDialer("", legacy)
	if err != nil {
		t.Fatalf("unpinned: %v", err)
	}
	defer d.Release()
	if d.Engine != "mihomo" {
		t.Errorf("unpinned engine = %q, want mihomo", d.Engine)
	}

	if pinned, err := NewDialer("xray", legacy); err == nil {
		pinned.Release()
		t.Error("a pinned xray dialer was built for a link xray refuses")
	}
}

func TestNewDialerKeepsASafetyRefusalOnXray(t *testing.T) {
	if fallback == nil || fallback.engine != "mihomo" || !hasLinkEngine("xray") {
		t.Skip("needs xray and the mihomo fallback")
	}
	d, err := NewDialer("", "trojan://secret@127.0.0.1:1?security=tls&sni=a.example&allowInsecure=1")
	if err == nil {
		d.Release()
		t.Fatalf("a dialer was built on %s for a link xray refuses for its safety", d.Engine)
	}
}
