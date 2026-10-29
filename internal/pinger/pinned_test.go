package pinger

import (
	"strings"
	"testing"
)

func hasMeasurer(engine string) bool {
	for _, m := range measurers {
		if m.engine == engine {
			return true
		}
	}
	return false
}

// A link xray refuses for a missing capability pings as unreachable on xray
// when xray is pinned, where the unpinned request carries it on mihomo.
func TestMeasurePinnedXrayDoesNotFallBackToMihomo(t *testing.T) {
	if fallback == nil || fallback.engine != "mihomo" || !hasMeasurer("xray") {
		t.Skip("needs xray and the mihomo fallback")
	}
	legacy := vmessLink(1, `"aid":"2","net":"tcp","type":"none","tls":""`)

	got := Measure(Request{Engine: "xray", Links: []string{legacy}, TimeoutMs: 1500})[0]
	if got.Engine != "xray" || got.Alive || got.Error == "" {
		t.Fatalf("pinned xray result = %+v, want a failure reported on xray", got)
	}
	if unpinned := Measure(Request{Links: []string{legacy}, TimeoutMs: 1500})[0]; unpinned.Engine != "mihomo" {
		t.Errorf("unpinned engine = %q, want mihomo", unpinned.Engine)
	}
}

func TestMeasurePinnedEngineRefusesALinkItDoesNotCarry(t *testing.T) {
	if fallback == nil || !hasMeasurer("xray") {
		t.Skip("needs xray and the mihomo fallback")
	}
	cases := []struct{ engine, link string }{
		{"xray", "hysteria2://auth@127.0.0.1:1#h"},
		{"xray", "awg://abc"},
		{"mihomo", "http://127.0.0.1:1"},
		{"mihomo", "https://127.0.0.1:1?sni=x"},
		{"awg", "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@127.0.0.1:1?type=tcp&security=tls"},
		{"nonesuch", "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@127.0.0.1:1?type=tcp&security=tls"},
	}
	for _, c := range cases {
		got := Measure(Request{Engine: c.engine, Links: []string{c.link}, TimeoutMs: 1500})[0]
		if got.Alive || got.Engine != c.engine || !strings.Contains(got.Error, "pinned engine") {
			t.Errorf("%s on %q: result = %+v, want refused as not carried", c.engine, c.link, got)
		}
	}
}

func TestMeasurePinnedMihomoMeasuresOnMihomo(t *testing.T) {
	if fallback == nil || fallback.engine != "mihomo" {
		t.Skip("needs the mihomo fallback")
	}
	got := Measure(Request{Engine: "mihomo", Links: []string{vmessLink(1, `"aid":"0","net":"tcp","type":"none","tls":""`)}, TimeoutMs: 1500})[0]
	if got.Engine != "mihomo" || got.Alive || got.Error == "" || strings.Contains(got.Error, "pinned engine") {
		t.Fatalf("result = %+v, want a dial failure on mihomo", got)
	}
}

// The awg engine cannot send WireGuard's reserved bytes: pinned to it, such a
// link is refused; unpinned, it pings on mihomo, which sends them.
func TestMeasureTakesReservedBytesToMihomo(t *testing.T) {
	if fallback == nil || fallback.engine != "mihomo" || !hasMeasurer("awg") {
		t.Skip("needs the awg measurer and the mihomo fallback")
	}

	pinned := Measure(Request{Engine: "awg", Links: []string{reservedWireGuardLink}, TimeoutMs: 1500})[0]
	if pinned.Engine != "awg" || pinned.Alive || !strings.Contains(pinned.Error, "reserved") {
		t.Errorf("pinned awg result = %+v, want the reserved-bytes refusal", pinned)
	}
	unpinned := Measure(Request{Links: []string{reservedWireGuardLink}, TimeoutMs: 1500})[0]
	if unpinned.Engine != "mihomo" || unpinned.Alive || strings.Contains(unpinned.Error, "reserved") {
		t.Errorf("unpinned result = %+v, want a dial failure on mihomo", unpinned)
	}
}

// reservedWireGuardLink sets reserved bytes; its keys are made up.
const reservedWireGuardLink = "wireguard://gTsOy%2FCY9QScEmonjo7Wt6yF7WxLJXOBgpd24MmUH0Y%3D@127.0.0.1:1" +
	"?publickey=kVNWJ0pOFM11%2Fp62BQNCmJQIffiVca8AipT6DTXxeVA%3D&address=10.0.0.2%2F32&reserved=1,2,3"

// The app runs WireGuard and AmneziaWG links on mihomo, reserved bytes
// included, so a ping pinned to mihomo measures them there.
func TestMeasurePinnedMihomoCarriesWireGuardLinks(t *testing.T) {
	if fallback == nil || fallback.engine != "mihomo" {
		t.Skip("needs the mihomo fallback")
	}
	for _, link := range []string{"awg://abc", reservedWireGuardLink} {
		got := Measure(Request{Engine: "mihomo", Links: []string{reservedWireGuardLink}, TimeoutMs: 1500})[0]
		if got.Engine != "mihomo" || got.Alive || got.Error == "" ||
			strings.Contains(got.Error, "pinned engine") || strings.Contains(got.Error, "reserved") {
			t.Errorf("%.20s: result = %+v, want a failure measured on mihomo", link, got)
		}
	}
}
