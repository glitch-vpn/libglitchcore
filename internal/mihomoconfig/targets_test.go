package mihomoconfig

import (
	"slices"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

const (
	namedPoolLink = "ss://chacha20-ietf-poly1305:pw@192.0.2.10:8388#pool"
	namedLinkOne  = "ss://chacha20-ietf-poly1305:pw@one.example:8388#one"
	namedLinkTwo  = "hysteria2://pw@two.example:443?insecure=1#two"
	namedLinkThr  = "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@192.0.2.13:443?type=tcp&security=none#three"
)

func namedProfile(routes ...routing.Route) routing.Profile {
	return routing.Profile{
		Tiers: []routing.Tier{{Routes: routes}},
		Targets: &routing.Targets{
			Version: 1,
			Servers: []routing.TargetServer{{ID: "s1", Link: namedLinkOne}, {ID: "s2", Link: namedLinkTwo}, {ID: "s3", Link: namedLinkThr}},
			Groups:  []routing.TargetGroup{{ID: "g1", Servers: []string{"s1", "s2"}}},
			Chains:  []routing.TargetChain{{ID: "c1", Hops: []string{"s1", "s2", "s3"}}},
		},
	}
}

func proxyNamed(t *testing.T, proxies []map[string]any, name string) map[string]any {
	t.Helper()
	for _, p := range proxies {
		if p["name"] == name {
			return p
		}
	}
	t.Fatalf("no proxy %q", name)
	return nil
}

func groupNamed(t *testing.T, groups []map[string]any, name string) map[string]any {
	t.Helper()
	for _, g := range groups {
		if g["name"] == name {
			return g
		}
	}
	t.Fatalf("no group %q", name)
	return nil
}

func TestNamedTargets_RawConfigStructure(t *testing.T) {
	prof := namedProfile(
		routing.Route{To: "s1", Match: []string{"full:a.example"}},
		routing.Route{To: "g1", Match: []string{"full:b.example"}},
		routing.Route{To: "c1", Match: []string{"full:c.example"}},
	)
	for _, links := range [][]string{{namedPoolLink}, {namedPoolLink, "ss://chacha20-ietf-poly1305:pw@192.0.2.14:8388#pool2"}} {
		raw, _, err := buildRaw(links, Inbound{MixedPort: 7890}, Options{Strategy: "fallback"}, prof)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"rt-s1", "rg-g1-0", "rg-g1-1", "rc-c1-0", "rc-c1-1", "rc-c1-2"} {
			proxyNamed(t, raw.Proxy, name)
		}
		group := groupNamed(t, raw.ProxyGroup, "rb-g1")
		if group["type"] != "fallback" || !slices.Equal(group["proxies"].([]string), []string{"rg-g1-0", "rg-g1-1"}) {
			t.Errorf("group = %+v", group)
		}
		for i, want := range []any{nil, "rc-c1-0", "rc-c1-1"} {
			got := proxyNamed(t, raw.Proxy, []string{"rc-c1-0", "rc-c1-1", "rc-c1-2"}[i])["dialer-proxy"]
			if got != want {
				t.Errorf("hop %d dialer-proxy = %v, want %v", i, got, want)
			}
		}
		if proxyNamed(t, raw.Proxy, "rt-s1")["dialer-proxy"] != nil {
			t.Error("a named server dials directly")
		}
		for i, p := range raw.Proxy[:len(links)] {
			if p["name"] == nil || len(links) != len(ProxyNames(links)) || p["name"] != ProxyNames(links)[i] {
				t.Errorf("pool proxy %d = %v: the pool keeps ProxyNames order first", i, p["name"])
			}
		}
	}
}

func TestNamedTargets_OnlyWhatARouteNamesIsBuilt(t *testing.T) {
	raw, _, err := buildRaw([]string{namedPoolLink}, Inbound{MixedPort: 7890}, Options{}, namedProfile(routing.Route{To: "s3", Match: []string{"full:a.example"}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw.Proxy) != 2 || len(raw.ProxyGroup) != 0 {
		t.Fatalf("proxies %d, groups %d", len(raw.Proxy), len(raw.ProxyGroup))
	}
}

func TestNamedTargets_RouteRulesFollowThePrecedence(t *testing.T) {
	prof := namedProfile(
		routing.Route{To: "g1", Match: []string{"full:both.example", "full:all.example"}},
		routing.Route{To: "s1", Match: []string{"full:both.example", "full:one.example", "full:direct.example"}},
		routing.Route{To: "c1", Match: []string{"full:chain.example"}},
	)
	prof.Tiers[0].Block = []string{"full:blocked.example", "full:all.example"}
	prof.Tiers[0].Direct = []string{"full:direct.example", "full:all.example"}
	prof.Tiers[0].Proxy = []string{"full:proxied.example", "full:blocked.example", "full:both.example"}
	cfg, err := BuildConfig([]string{namedPoolLink}, Inbound{MixedPort: 7890}, Options{}, prof)
	if err != nil {
		t.Fatal(err)
	}
	tcp, in := C.TCP, "test"
	routeFlows(t, cfg, namedPoolName, []routedFlow{
		{"block beats proxy", in, tcp, "blocked.example", "", "", "REJECT"},
		{"block beats direct and routes", in, tcp, "all.example", "", "", "REJECT"},
		{"direct beats a route", in, tcp, "direct.example", "", "", "DIRECT"},
		{"the first route wins, and beats proxy", in, tcp, "both.example", "", "", "rb-g1"},
		{"a server route", in, tcp, "one.example", "", "", "rt-s1"},
		{"a chain routes to its last hop", in, tcp, "chain.example", "", "", "rc-c1-2"},
		{"proxy", in, tcp, "proxied.example", "", "", "target"},
		{"unmatched takes the catch-all", in, tcp, "other.example", "", "", "target"},
	})
}

const namedPoolName = "pool"

func TestNamedTargets_GeneratedNamesYieldToLinkNames(t *testing.T) {
	links := []string{"ss://chacha20-ietf-poly1305:pw@192.0.2.10:8388#rt-s1", "ss://chacha20-ietf-poly1305:pw@192.0.2.11:8388#rb-g1"}
	prof := namedProfile(
		routing.Route{To: "s1", Match: []string{"full:a.example"}},
		routing.Route{To: "g1", Match: []string{"full:b.example"}},
	)
	raw, _, err := buildRaw(links, Inbound{MixedPort: 7890}, Options{}, prof)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[any]bool{}
	for _, p := range append(slices.Clone(raw.Proxy), raw.ProxyGroup...) {
		if seen[p["name"]] {
			t.Fatalf("name %v is used twice", p["name"])
		}
		seen[p["name"]] = true
	}
	if _, err := BuildConfig(links, Inbound{MixedPort: 7890}, Options{}, prof); err != nil {
		t.Fatalf("mihomo refused the config: %v", err)
	}
}

func TestNamedTargets_Refusals(t *testing.T) {
	mutate := func(f func(*routing.Profile)) routing.Profile {
		p := namedProfile(routing.Route{To: "c1", Match: []string{"full:c.example"}})
		f(&p)
		return p
	}
	cases := map[string]routing.Profile{
		"an undefined route target": mutate(func(p *routing.Profile) { p.Tiers[0].Routes[0].To = "nope" }),
		"a server mihomo cannot build": mutate(func(p *routing.Profile) {
			p.Targets.Servers[1].Link = "http://user:pw@192.0.2.20:8080#h"
		}),
	}
	for name, prof := range cases {
		if _, err := BuildConfig([]string{namedPoolLink}, Inbound{MixedPort: 7890}, Options{}, prof); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
}
