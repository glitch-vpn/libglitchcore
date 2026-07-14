package routing

import "testing"

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
}

func TestProcessRules(t *testing.T) {
	p := Profile{
		Proxy:  []string{"process:Steam.exe", "domain:youtube.com"},
		Direct: []string{"process:Discord.exe", "geoip:ru"},
		Block:  []string{"process:Ads.exe", "process:Discord.exe"},
	}
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
