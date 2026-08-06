package core

import (
	"encoding/json"
	"runtime"
	"slices"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

func TestRoutingFromOpts_Tiers(t *testing.T) {
	// Legacy keys produce one tier, byte-identical to the old flat profile;
	// bypassCountries stays a Direct geoip alias.
	p, err := routingFromOpts(map[string]string{
		"routingMode":     "direct-all",
		"proxyRules":      "domain:youtube.com, geosite:youtube",
		"directRules":     "geoip:ru",
		"blockRules":      "geosite:ads",
		"bypassCountries": "KZ,BY",
	})
	if err != nil {
		t.Fatalf("legacy keys: %v", err)
	}
	want := routing.Profile{
		Mode: "direct-all",
		Tiers: []routing.Tier{{
			Block:  []string{"geosite:ads"},
			Direct: []string{"geoip:ru", "geoip:kz", "geoip:by"},
			Proxy:  []string{"domain:youtube.com", "geosite:youtube"},
		}},
	}
	if got, exp := jsonOf(t, p), jsonOf(t, want); got != exp {
		t.Errorf("legacy profile = %s, want %s", got, exp)
	}

	// No rule keys at all -> no tiers.
	p, err = routingFromOpts(map[string]string{"routingMode": "proxy-all"})
	if err != nil || len(p.Tiers) != 0 {
		t.Errorf("empty opts: tiers = %v, err = %v; want none, nil", p.Tiers, err)
	}

	// routingTiers wins; legacy keys are ignored.
	p, err = routingFromOpts(map[string]string{
		"routingTiers": `[{"proxy":["domain:vk.ru"]},{"direct":["domain:ru"]}]`,
		"directRules":  "geoip:ru",
	})
	if err != nil {
		t.Fatalf("routingTiers: %v", err)
	}
	wantTiers := []routing.Tier{
		{Proxy: []string{"domain:vk.ru"}},
		{Direct: []string{"domain:ru"}},
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

func TestOptsFromRequest_GeoAssetsDir(t *testing.T) {
	abs := `C:\geo\assets`
	if runtime.GOOS != "windows" {
		abs = "/opt/geo/assets"
	}
	o, err := optsFromRequest(EngineStartRequest{Opts: map[string]string{"geoAssetsDir": " " + abs + " "}})
	if err != nil || o.geoAssetsDir != abs {
		t.Errorf("abs path: geoAssetsDir = %q, err = %v; want %q", o.geoAssetsDir, err, abs)
	}
	// Relative paths are meaningless in a service process with an unknown
	// working directory - ignored, not failed.
	o, err = optsFromRequest(EngineStartRequest{Opts: map[string]string{"geoAssetsDir": "relative/dir"}})
	if err != nil || o.geoAssetsDir != "" {
		t.Errorf("relative path: geoAssetsDir = %q, err = %v; want ignored", o.geoAssetsDir, err)
	}
	o, err = optsFromRequest(EngineStartRequest{})
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
