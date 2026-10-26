package core

import (
	"encoding/json"
	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

func TestRoutingFromOpts_Tiers(t *testing.T) {
	p, err := routingFromOpts(map[string]string{"routingMode": "proxy-all"})
	if err != nil || len(p.Tiers) != 0 {
		t.Errorf("empty opts: tiers = %v, err = %v; want none, nil", p.Tiers, err)
	}

	p, err = routingFromOpts(map[string]string{
		"routingTiers": `[{"proxy":["domain:vk.ru","process:My, App.exe"]},{"direct":["domain:ru","regexp:^x{1,3}\\.ru$"]}]`,
	})
	if err != nil {
		t.Fatalf("routingTiers: %v", err)
	}
	wantTiers := []routing.Tier{
		{Proxy: []string{"domain:vk.ru", "process:My, App.exe"}},
		{Direct: []string{"domain:ru", `regexp:^x{1,3}\.ru$`}},
	}
	if got, exp := jsonOf(t, p.Tiers), jsonOf(t, wantTiers); got != exp {
		t.Errorf("tiers = %s, want %s", got, exp)
	}

	// Malformed routingTiers fails the start - never silently drops rules.
	for _, bad := range []string{"not json", `{"block":[]}`, `[1,2]`, `[{"block":"x"}]`, "null", `[] []`} {
		if _, err := routingFromOpts(map[string]string{"routingTiers": bad}); err == nil {
			t.Errorf("routingTiers %q: want error, got nil", bad)
		}
	}
}

// A caller still on the CSV keys would connect without the rules it means;
// the start fails instead, even beside routingTiers and even when empty.
func TestRoutingFromOpts_LegacyKeysRefused(t *testing.T) {
	for _, key := range legacyRuleKeys {
		for _, opts := range []map[string]string{
			{key: "geoip:ru"},
			{key: ""},
			{key: "geoip:ru", "routingTiers": `[{"proxy":["domain:vk.ru"]}]`},
		} {
			_, err := routingFromOpts(opts)
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Errorf("opts %v: err = %v, want a refusal naming %s", opts, err, key)
			}
		}
	}
}

// A comma in a domain value would split mihomo's rule line and could re-target
// the rule, so the start fails on every engine alike.
func TestRoutingFromOpts_CommaInDomainRefused(t *testing.T) {
	for _, tiers := range []string{
		`[{"block":["domain:example.com,DIRECT"]}]`,
		`[{"proxy":["full:a.example,b.example"]}]`,
		`[{"direct":["keyword:ads,REJECT"]}]`,
		`[{"proxy":["domain:vk.ru"]},{"block":["ads.example,DIRECT"]}]`,
		`[{"block":["regexp:^(a|b) , c$"]}]`,
	} {
		if _, err := routingFromOpts(map[string]string{"routingTiers": tiers}); err == nil {
			t.Errorf("routingTiers %s: want error, got nil", tiers)
		}
	}
}

func TestOptsFromRequest_GeoAssetsDir(t *testing.T) {
	abs := `C:\geo\assets`
	if runtime.GOOS != "windows" {
		abs = "/opt/geo/assets"
	}
	o, err := optsFromRequest(EngineStartRequest{Opts: map[string]string{"geoAssetsDir": " " + abs + " "}}, "xray")
	if err != nil || o.geoAssetsDir != abs {
		t.Errorf("abs path: geoAssetsDir = %q, err = %v; want %q", o.geoAssetsDir, err, abs)
	}
	// Relative paths are meaningless in a service process with an unknown
	// working directory - ignored, not failed.
	o, err = optsFromRequest(EngineStartRequest{Opts: map[string]string{"geoAssetsDir": "relative/dir"}}, "xray")
	if err != nil || o.geoAssetsDir != "" {
		t.Errorf("relative path: geoAssetsDir = %q, err = %v; want ignored", o.geoAssetsDir, err)
	}
	o, err = optsFromRequest(EngineStartRequest{}, "xray")
	if err != nil || o.geoAssetsDir != "" {
		t.Errorf("absent: geoAssetsDir = %q, err = %v; want empty", o.geoAssetsDir, err)
	}
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestEngineDispatch_UnknownEngineRejected(t *testing.T) {
	ctl := &CoreController{}
	ctl.initEngineState()

	if got := ctl.engineStart("nope", EngineStartRequest{}); got != glitchCoreResultError {
		t.Errorf("engineStart(unknown) = %d, want error %d", got, glitchCoreResultError)
	}
	if got := ctl.engineStop("nope"); got != glitchCoreResultError {
		t.Errorf("engineStop(unknown) = %d, want error %d", got, glitchCoreResultError)
	}
	if got := ctl.engineIsRunning("nope"); got != glitchCoreResultError {
		t.Errorf("engineIsRunning(unknown) = %d, want error %d", got, glitchCoreResultError)
	}
}

func TestCoreCapabilities_JSONShape(t *testing.T) {
	var caps struct {
		Engines  []string          `json:"engines"`
		Versions map[string]string `json:"versions"`
	}
	if err := json.Unmarshal([]byte(coreCapabilities()), &caps); err != nil {
		t.Fatalf("coreCapabilities() is not valid JSON: %v", err)
	}
	// Engines are sorted and mirror the registry exactly, whatever this build's
	// composition is (multi: awg/mihomo/xray; solo: mihomo).
	if !slices.IsSorted(caps.Engines) {
		t.Errorf("engines %v not sorted", caps.Engines)
	}
	if len(caps.Engines) != len(engineRegistry) {
		t.Errorf("engines %v, want %d entries (one per registered engine)", caps.Engines, len(engineRegistry))
	}
	for id := range engineRegistry {
		if !slices.Contains(caps.Engines, id) {
			t.Errorf("engines %v missing registered engine %q", caps.Engines, id)
		}
	}
	if caps.Versions == nil {
		t.Error("versions map missing")
	}
}

func TestDNSFromRequest_FilterIsCheckedWhereTheEngineReadsIt(t *testing.T) {
	bad := []string{"a*b"}
	tunnel := map[string]string{}
	proxy := map[string]string{"proxyPort": "1080"}
	cases := []struct {
		name    string
		engine  string
		mode    string
		opts    map[string]string
		refused bool
	}{
		{"mihomo tunnel, unset mode runs fake-ip", "mihomo", "", tunnel, true},
		{"mihomo tunnel, fake-ip", "mihomo", dnsconfig.ModeFakeIP, tunnel, true},
		{"mihomo tunnel, normal", "mihomo", dnsconfig.ModeNormal, tunnel, false},
		{"mihomo proxy mode, fake-ip", "mihomo", dnsconfig.ModeFakeIP, proxy, false},
		{"mihomo proxy mode, unset", "mihomo", "", proxy, false},
		{"xray, unset mode is not fake-ip", "xray", "", tunnel, false},
		{"awg reads none", "awg", dnsconfig.ModeFakeIP, tunnel, false},
	}
	for _, c := range cases {
		req := EngineStartRequest{Opts: c.opts, DNSConfig: &dnsconfig.Config{Mode: c.mode, FakeIPFilter: bad}}
		_, err := dnsFromRequest(req, c.engine)
		if (err != nil) != c.refused {
			t.Errorf("%s: err = %v, want refused = %v", c.name, err, c.refused)
		}
	}
	// A filter xray reads as another matcher is refused on xray in fake-ip mode.
	req := EngineStartRequest{DNSConfig: &dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, FakeIPFilter: []string{"keyword:domain:x.com"}}}
	if _, err := dnsFromRequest(req, "xray"); err == nil {
		t.Error("xray fake-ip: keyword that reads as a matcher was accepted")
	}
}
