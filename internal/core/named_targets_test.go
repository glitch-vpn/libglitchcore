package core

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

const (
	namedTargetsOpt = `{"version":1,"servers":[{"id":"s1","link":"ss://chacha20-ietf-poly1305:pw@192.0.2.1:8388#one"},{"id":"s2","link":"ss://chacha20-ietf-poly1305:pw@192.0.2.2:8388#two"}],"groups":[{"id":"g1","servers":["s1","s2"]}],"chains":[{"id":"c1","hops":["s1","s2"]}]}`
	namedTiersOpt   = `[{"block":["domain:blocked.example"],"routes":[{"to":"g1","match":["domain:a.example"]},{"to":"c1","match":["domain:b.example"]}],"proxy":["domain:c.example"]}]`
)

func TestRoutingFromOpts_RoutesAndTargets(t *testing.T) {
	p, err := routingFromOpts(map[string]string{"routingTiers": namedTiersOpt, "routingTargets": namedTargetsOpt})
	if err != nil {
		t.Fatalf("routes with targets: %v", err)
	}
	if p.Targets == nil || len(p.Targets.Servers) != 2 || len(p.Targets.Groups) != 1 || len(p.Targets.Chains) != 1 {
		t.Fatalf("targets = %+v", p.Targets)
	}
	wantRoutes := []routing.Route{{To: "g1", Match: []string{"domain:a.example"}}, {To: "c1", Match: []string{"domain:b.example"}}}
	if got, want := jsonOf(t, p.Tiers[0].Routes), jsonOf(t, wantRoutes); got != want {
		t.Errorf("routes = %s, want %s", got, want)
	}

	plain, err := routingFromOpts(map[string]string{"routingTiers": `[{"proxy":["domain:vk.ru"]}]`})
	if err != nil || plain.Targets != nil {
		t.Errorf("a start without targets carries none: %+v, %v", plain.Targets, err)
	}
}

// A start that names what it cannot reach must fail, not fall back to the
// pool, to direct or to no rule at all.
func TestRoutingFromOpts_RefusesWhatARouteCannotReach(t *testing.T) {
	routed := func(to string) string {
		return `[{"routes":[{"to":"` + to + `","match":["domain:a.example"]}]}]`
	}
	cases := []struct {
		name string
		opts map[string]string
		want string
	}{
		{"an undefined id", map[string]string{"routingTiers": routed("nope"), "routingTargets": namedTargetsOpt}, "nope"},
		{"routes without targets", map[string]string{"routingTiers": routed("s1")}, "s1"},
		{"an unknown version", map[string]string{"routingTargets": strings.Replace(namedTargetsOpt, `"version":1`, `"version":2`, 1)}, "version"},
		{"a misspelled key", map[string]string{"routingTargets": strings.Replace(namedTargetsOpt, `"hops"`, `"hop"`, 1)}, "hop"},
		{"a duplicate id", map[string]string{"routingTargets": strings.Replace(namedTargetsOpt, `"id":"g1"`, `"id":"s1"`, 1)}, "duplicate"},
		{"an empty group", map[string]string{"routingTargets": strings.Replace(namedTargetsOpt, `"servers":["s1","s2"]}],"chains"`, `"servers":[]}],"chains"`, 1)}, "empty"},
		{"a one-hop chain", map[string]string{"routingTargets": strings.Replace(namedTargetsOpt, `"hops":["s1","s2"]`, `"hops":["s1"]`, 1)}, "hops"},
		{"a repeated hop", map[string]string{"routingTargets": strings.Replace(namedTargetsOpt, `"hops":["s1","s2"]`, `"hops":["s1","s1"]`, 1)}, "twice"},
		{"a process matcher in a route", map[string]string{
			"routingTiers":   `[{"routes":[{"to":"s1","match":["process:app.exe"]}]}]`,
			"routingTargets": namedTargetsOpt,
		}, "process"},
		{"null targets", map[string]string{"routingTargets": "null"}, "null"},
		{"trailing data", map[string]string{"routingTargets": namedTargetsOpt + namedTargetsOpt}, "trailing"},
	}
	for _, c := range cases {
		_, err := routingFromOpts(c.opts)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one naming %q", c.name, err, c.want)
		}
	}
}

// A core that predates routes decodes a tier with DisallowUnknownFields, so a
// caller that checks the feature before sending routes is never refused late.
func TestCoreCapabilities_NamesRouteTargets(t *testing.T) {
	var caps struct {
		Features []string `json:"features"`
	}
	if err := json.Unmarshal([]byte(coreCapabilities()), &caps); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(caps.Features, "routeTargets") {
		t.Errorf("features %v lack routeTargets", caps.Features)
	}
}
