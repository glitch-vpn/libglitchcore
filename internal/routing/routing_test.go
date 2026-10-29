package routing

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		kind MatchKind
		val  string
	}{
		{"geoip:CN", KindGeoIP, "cn"},
		{"geosite:category-ru", KindGeoSite, "category-ru"},
		{"domain:рф", KindDomainSuffix, "рф"},
		{"full:exact.example", KindDomainFull, "exact.example"},
		{"keyword:ads", KindDomainKeyword, "ads"},
		{"regexp:.*\\.cn$", KindDomainRegex, ".*\\.cn$"},
		{"process:Discord.exe", KindProcess, "Discord.exe"},
		{"48.123.243.123", KindIPCIDR, "48.123.243.123"},
		{"10.0.0.0/8", KindIPCIDR, "10.0.0.0/8"},
		{"2001:db8::/32", KindIPCIDR, "2001:db8::/32"},
		{"::/0", KindIPCIDR, "::/0"},
		{"youtube.com", KindDomainSuffix, "youtube.com"},
		// Dots around a zone are stripped: both engines match on label
		// boundaries, so ".ru" would match nothing.
		{"domain:.ru", KindDomainSuffix, "ru"},
		{".ru", KindDomainSuffix, "ru"},
		{"domain:example.ru.", KindDomainSuffix, "example.ru"},
		{"full:.exact.example.", KindDomainFull, "exact.example"},
		// Substring and regex values keep their dots.
		{"keyword:.ru", KindDomainKeyword, ".ru"},
		{"regexp:.*\\.ru$", KindDomainRegex, ".*\\.ru$"},
	}
	for _, c := range cases {
		kind, val, ok := Classify(c.in)
		if !ok || kind != c.kind || val != c.val {
			t.Errorf("Classify(%q) = (%v,%q,%v), want (%v,%q,true)", c.in, kind, val, ok, c.kind, c.val)
		}
	}
	if _, _, ok := Classify("  "); ok {
		t.Error("blank entry should be !ok")
	}
	for _, dots := range []string{".", "..", "domain:.", "full: . "} {
		if _, _, ok := Classify(dots); ok {
			t.Errorf("Classify(%q) should be !ok (nothing left after trimming dots)", dots)
		}
	}
}

func TestValidGeoCodeCharset(t *testing.T) {
	geosite := []struct {
		in string
		ok bool
	}{
		{"cn", true},
		{"category-ads-all", true},
		{"geolocation-!cn", true},
		{"cn@ads", true},
		// Leading '!' is mihomo's inverse syntax; xray looks up a list named
		// "!CN" and hard-fails the config, so it stays rejected for geosite.
		{"!cn", false},
		{"cn@ads@extra", true},
		{"рф", false},
		{"cn@", false},
		{"@ads", false},
		{"cn@@ads", false},
		{"", false},
	}
	for _, c := range geosite {
		if got := ValidGeoCode(c.in); got != c.ok {
			t.Errorf("ValidGeoCode(%q) = %v, want %v", c.in, got, c.ok)
		}
	}
	geoip := []struct {
		in string
		ok bool
	}{
		{"ru", true},
		{"!ru", true},
		{"private", true},
		{"r!u", false},
		{"cn@ads", false},
		{"рф", false},
		{"!", false},
		{"", false},
	}
	for _, c := range geoip {
		if got := ValidGeoIPCode(c.in); got != c.ok {
			t.Errorf("ValidGeoIPCode(%q) = %v, want %v", c.in, got, c.ok)
		}
	}
}

func TestProcessRules(t *testing.T) {
	p := Profile{Tiers: []Tier{{
		Proxy:  []string{"process:Steam.exe", "domain:youtube.com"},
		Direct: []string{"process:Discord.exe", "geoip:ru"},
		Block:  []string{"process:Ads.exe", "process:Discord.exe"},
	}}}
	got := ProcessRules(p)
	want := map[string]string{
		"steam.exe":   TargetProxy,
		"discord.exe": TargetBlock, // block > direct
		"ads.exe":     TargetBlock,
	}
	if len(got) != len(want) {
		t.Fatalf("ProcessRules = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ProcessRules[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestProcessRules_AcrossTiers(t *testing.T) {
	// The per-process dialer consumes one flat map: the global priority
	// block > direct > proxy holds across tiers, regardless of tier order.
	p := Profile{Tiers: []Tier{
		{Proxy: []string{"process:App.exe"}},
		{Block: []string{"process:App.exe"}, Direct: []string{"process:Tool.exe"}},
	}}
	got := ProcessRules(p)
	if got["app.exe"] != TargetBlock {
		t.Errorf("app.exe = %q, want block (block beats proxy across tiers)", got["app.exe"])
	}
	if got["tool.exe"] != TargetDirect {
		t.Errorf("tool.exe = %q, want direct", got["tool.exe"])
	}
}

// A tier's entries come out most specific first, the categories as one rank,
// an app's block first and its other entries last; equal rank falls back to
// block, direct, proxy.
func TestTierEntries_SpecificFirst(t *testing.T) {
	tier := Tier{
		Block:  []string{"geosite:ads", "process:Ads.exe", "domain:x.ru", "10.0.0.0/8"},
		Direct: []string{"geoip:ru", "domain:ru", "process:Tool.exe", "keyword:shop", "10.1.0.0/16", "domain:x.ru"},
		Proxy:  []string{"domain:vk.ru", "full:api.x.ru", "process:App.exe", "regexp:^a", "10.1.2.3", "geoip:ru", "domain:x.ru"},
	}
	var got []string
	for _, e := range tier.Entries() {
		got = append(got, e.Target+" "+e.Value)
	}
	want := []string{
		"block Ads.exe",
		"proxy api.x.ru",
		"block x.ru",
		"direct x.ru",
		"proxy vk.ru",
		"proxy x.ru",
		"direct ru",
		"proxy 10.1.2.3",
		"direct 10.1.0.0/16",
		"block 10.0.0.0/8",
		"direct shop",
		"proxy ^a",
		"block ads",
		"direct ru",
		"proxy ru",
		"direct Tool.exe",
		"proxy App.exe",
	}
	if g, w := strings.Join(got, "\n"), strings.Join(want, "\n"); g != w {
		t.Fatalf("Entries =\n%s\nwant\n%s", g, w)
	}
}

// A direct run is paired with the other plane up to its last block, keeping
// its own outcome where that plane's exception comes first.
func TestTierSteps_BlockYieldsOnlyInItsPlane(t *testing.T) {
	tier := Tier{
		Block:  []string{"192.0.2.0/24", "geosite:ads"},
		Direct: []string{"domain:x.test", "192.0.2.7"},
		Proxy:  []string{"process:App.exe"},
	}
	var got []string
	for _, step := range tier.Steps() {
		line := step.Target
		for _, e := range step.Entries {
			line += " " + e.Value
		}
		if len(step.Also) > 0 {
			line += " &"
			for _, e := range step.Also {
				line += " " + e.Value
			}
		}
		got = append(got, line)
	}
	want := []string{
		"direct x.test & 192.0.2.7",
		"block x.test & 192.0.2.0/24",
		"direct x.test",
		"direct 192.0.2.7 & x.test",
		"block 192.0.2.7 & ads",
		"direct 192.0.2.7",
		"block 192.0.2.0/24",
		"block ads",
		"proxy App.exe",
	}
	if g, w := strings.Join(got, "\n"), strings.Join(want, "\n"); g != w {
		t.Fatalf("Steps =\n%s\nwant\n%s", g, w)
	}
}

func TestValidateRefusesWhatEnginesWouldDrop(t *testing.T) {
	cases := []struct {
		matcher, want string
	}{
		{"geoip:рф", "invalid geoip code"},
		{"geoip:r,u", "invalid geoip code"},
		{"geosite:рф", "invalid geosite code"},
		{"geosite:a,b", "invalid geosite code"},
		{"geosite:!cn", "invalid geosite code"},
		{"keyword:domain:example.com", `cannot start with "domain:"`},
		{"keyword:full:example.com", `cannot start with "full:"`},
		{"keyword:regexp:^a", `cannot start with "regexp:"`},
		{"keyword:geosite:cn", `cannot start with "geosite:"`},
		{"keyword:ext:file.dat:tag", `cannot start with "ext:"`},
		{"keyword:keyword:ads", `cannot start with "keyword:"`},
		{`regexp:^a\(b$`, "parentheses must pair up"},
		{"regexp:^a)(b$", "parentheses must pair up"},
		{"keyword:a(b", "parentheses must pair up"},
		{"domain:a)b.example", "parentheses must pair up"},
	}
	for _, c := range cases {
		for _, tier := range []Tier{{Block: []string{c.matcher}}, {Direct: []string{c.matcher}}, {Proxy: []string{c.matcher}}} {
			err := Profile{Tiers: []Tier{tier}}.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Validate(%q) = %v, want an error naming %q", c.matcher, err, c.want)
			}
		}
	}
}

func TestValidateKeepsWhatEnginesCarry(t *testing.T) {
	p := Profile{Tiers: []Tier{{
		Block:  []string{"geoip:!ru", "geosite:geolocation-!cn", "geosite:cn@ads", "keyword:ads", "keyword:.ru", "keyword:domainer"},
		Direct: []string{"geoip:private", "domain:рф", "keyword:a:b", `regexp:^\(a\)(b|c)$`},
	}}}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate = %v, want nil", err)
	}
}
