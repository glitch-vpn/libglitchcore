package routing

import (
	"strings"
	"testing"
)

func twoServers() *Targets {
	return &Targets{
		Version: 1,
		Servers: []TargetServer{{ID: "s1", Link: "ss://a"}, {ID: "s2", Link: "ss://b"}, {ID: "s3", Link: "ss://c"}},
		Groups:  []TargetGroup{{ID: "g1", Servers: []string{"s1", "s2"}}},
		Chains:  []TargetChain{{ID: "c1", Hops: []string{"s1", "s2"}}},
	}
}

func routed(to string, match ...string) Profile {
	return Profile{Tiers: []Tier{{Routes: []Route{{To: to, Match: match}}}}, Targets: twoServers()}
}

func TestValidateTargets(t *testing.T) {
	mutate := func(f func(*Targets)) *Targets {
		tg := twoServers()
		f(tg)
		return tg
	}
	cases := []struct {
		name string
		t    *Targets
		want string
	}{
		{"unknown version", mutate(func(t *Targets) { t.Version = 2 }), "version"},
		{"duplicate id", mutate(func(t *Targets) { t.Groups[0].ID = "s1" }), "duplicate"},
		{"duplicate id across kinds", mutate(func(t *Targets) { t.Chains[0].ID = "g1" }), "duplicate"},
		{"bad id", mutate(func(t *Targets) { t.Servers[0].ID = "S-1" }), "id"},
		{"long id", mutate(func(t *Targets) { t.Servers[0].ID = strings.Repeat("a", 17) }), "id"},
		{"empty link", mutate(func(t *Targets) { t.Servers[0].Link = " " }), "link"},
		{"empty group", mutate(func(t *Targets) { t.Groups[0].Servers = nil }), "empty"},
		{"unknown group member", mutate(func(t *Targets) { t.Groups[0].Servers = []string{"zz"} }), "unknown"},
		{"chain of one", mutate(func(t *Targets) { t.Chains[0].Hops = []string{"s1"} }), "2.."},
		{"chain over the cap", mutate(func(t *Targets) {
			t.Servers = append(t.Servers, TargetServer{ID: "s4", Link: "x"}, TargetServer{ID: "s5", Link: "x"})
			t.Chains[0].Hops = []string{"s1", "s2", "s3", "s4", "s5"}
		}), "2.."},
		{"repeated hop", mutate(func(t *Targets) { t.Chains[0].Hops = []string{"s1", "s2", "s1"} }), "twice"},
		{"group as a hop", mutate(func(t *Targets) { t.Chains[0].Hops = []string{"s1", "g1"} }), "unknown"},
		{"too many servers", mutate(func(t *Targets) {
			t.Servers = nil
			t.Groups, t.Chains = nil, nil
			for i := 0; i < 65; i++ {
				t.Servers = append(t.Servers, TargetServer{ID: "a" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Link: "x"})
			}
		}), "64"},
	}
	for _, c := range cases {
		p := Profile{Targets: c.t}
		err := p.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one naming %q", c.name, err, c.want)
		}
	}
	if err := (Profile{Targets: twoServers()}).Validate(); err != nil {
		t.Fatalf("valid targets refused: %v", err)
	}
}

func TestValidateRoutes(t *testing.T) {
	for _, to := range []string{"s1", "g1", "c1"} {
		if err := routed(to, "domain:a.example").Validate(); err != nil {
			t.Errorf("route to %s refused: %v", to, err)
		}
	}
	if err := routed("nope", "domain:a.example").Validate(); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("undefined id: err = %v", err)
	}
	noTargets := Profile{Tiers: []Tier{{Routes: []Route{{To: "s1", Match: []string{"a.example"}}}}}}
	if err := noTargets.Validate(); err == nil {
		t.Error("a route with no targets must be refused")
	}
	if err := routed("s1", "process:app.exe").Validate(); err == nil || !strings.Contains(err.Error(), "process") {
		t.Errorf("process matcher in a route: err = %v", err)
	}
	if err := routed("s1", "keyword:domain:x").Validate(); err == nil {
		t.Error("a route's matchers are validated like any tier's")
	}
}

func TestRouteEntriesPrecedence(t *testing.T) {
	tier := Tier{
		Block:  []string{"geosite:x"},
		Direct: []string{"geosite:x"},
		Proxy:  []string{"geosite:x"},
		Routes: []Route{{To: "g1", Match: []string{"geosite:x"}}, {To: "s1", Match: []string{"geosite:x"}}},
	}
	var got []string
	for _, e := range tier.Entries() {
		got = append(got, e.Target+":"+e.To)
	}
	want := []string{"block:", "direct:", "route:g1", "route:s1", "proxy:"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestRouteStepsKeepTheirTarget(t *testing.T) {
	tier := Tier{Routes: []Route{
		{To: "s1", Match: []string{"full:a.example"}},
		{To: "s2", Match: []string{"full:b.example"}},
	}}
	steps := tier.Steps()
	if len(steps) != 2 || steps[0].To != "s1" || steps[1].To != "s2" || steps[0].Target != TargetRoute {
		t.Fatalf("steps = %+v, want one route step per target", steps)
	}
}

func TestRouteGuardedByAnAddressBlock(t *testing.T) {
	tier := Tier{
		Block:  []string{"10.0.0.0/8"},
		Routes: []Route{{To: "s1", Match: []string{"domain:a.example"}}},
	}
	var guarded bool
	for _, s := range tier.Steps() {
		if s.Target == TargetRoute && len(s.Also) > 0 {
			t.Errorf("a guard step toward the route must carry its target, got %+v", s)
		}
		if s.Target == TargetRoute && s.To != "s1" {
			t.Errorf("route step lost its target: %+v", s)
		}
		if s.Target == TargetBlock && len(s.Also) > 0 {
			guarded = true
		}
	}
	if !guarded {
		t.Error("an address block must guard the route's names")
	}
}
