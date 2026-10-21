package mihomoconfig

import (
	"net/url"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
	C "github.com/metacubex/mihomo/constant"
)

// ProxyNames must reproduce BuildConfig's naming exactly - the selection
// watcher maps a group's Now() back to a link index through it.
func TestProxyNames(t *testing.T) {
	names := ProxyNames([]string{
		"vless://u@a.example.com:443#Alpha",
		"",
		"vless://u@b.example.com:443",       // no fragment -> positional fallback
		"vless://u@c.example.com:443#Alpha", // duplicate remark -> uniquified
	})
	want := []string{"Alpha", "proxy-2", "Alpha (2)"}
	if len(names) != len(want) {
		t.Fatalf("names = %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("names[%d] = %q, want %q (all: %v)", i, names[i], want[i], names)
		}
	}
}

func TestProxyNames_StepsAroundReservedNames(t *testing.T) {
	names := ProxyNames([]string{
		"vless://u@a.example.com:443#GLOBAL%20(2)",
		"vless://u@b.example.com:443#GLOBAL",
	})
	if len(names) != 2 || names[0] != "GLOBAL (2)" || names[1] != "GLOBAL (3)" {
		t.Fatalf("names = %v, want [GLOBAL (2) GLOBAL (3)]", names)
	}
}

func TestTarget_ProxyOrBalancerGroup(t *testing.T) {
	one := []string{"ss://aes-128-gcm:pass@5.6.7.8:8388#solo"}
	if got := Target(one); got != "solo" {
		t.Fatalf("Target(one link) = %q, want the proxy's name", got)
	}
	if got := Target(append(one, "ss://aes-128-gcm:pass@5.6.7.9:8388#other")); got != GroupTag {
		t.Fatalf("Target(two links) = %q, want %q", got, GroupTag)
	}
}

func reservedNamesTestLink(host, remark string) string {
	return "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@" + host + ":443?type=tcp&security=none#" + url.PathEscape(remark)
}

// The names mihomo's parser puts into every config on its own, read from a
// config it parsed rather than written down, so a mihomo upgrade that adds one
// shows up here.
func mihomoBuiltInNames(t *testing.T) []string {
	t.Helper()
	links := []string{reservedNamesTestLink("1.2.3.4", "own")}
	cfg, err := BuildConfig(links, Inbound{MixedPort: 17890}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	var names []string
	for name := range cfg.Proxies {
		if name != "own" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		t.Fatal("mihomo defined no names of its own")
	}
	return names
}

// A remark naming a built-in, or the balancer group, must still name the
// server itself: the rules' target and every group member resolve to it.
func TestBuildConfig_RemarkNeverAliasesABuiltInName(t *testing.T) {
	for _, name := range append(mihomoBuiltInNames(t), GroupTag) {
		t.Run(name, func(t *testing.T) {
			own := reservedNamesTestLink("1.2.3.4", name)
			other := reservedNamesTestLink("1.2.3.5", "other")
			for _, links := range [][]string{{own}, {own, other}} {
				cfg, err := BuildConfig(links, Inbound{MixedPort: 17890}, Options{}, routing.Profile{})
				if err != nil {
					t.Fatalf("%d link(s): BuildConfig: %v", len(links), err)
				}
				for _, proxyName := range ProxyNames(links) {
					if p := cfg.Proxies[proxyName]; p == nil || p.Type() != C.Vless {
						t.Fatalf("%d link(s): proxy %q resolves to %v, want the vless server", len(links), proxyName, p)
					}
				}
				match := cfg.Rules[len(cfg.Rules)-1]
				if match.RuleType() != C.MATCH || match.Adapter() != Target(links) {
					t.Fatalf("%d link(s): last rule %s -> %s, want MATCH -> %s", len(links), match.RuleType(), match.Adapter(), Target(links))
				}
				target := cfg.Proxies[Target(links)]
				if len(links) == 1 && (target == nil || target.Type() != C.Vless) {
					t.Fatalf("MATCH target %q resolves to %v, want the vless server", Target(links), target)
				}
				if len(links) > 1 && (target == nil || target.Type() != C.URLTest) {
					t.Fatalf("MATCH target %q resolves to %v, want the balancer group", Target(links), target)
				}
			}
		})
	}
}
