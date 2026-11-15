package xrayconfig

import (
	"strings"
	"testing"

	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// serverList renders the resolvers as "address", "address#tag" for one with
// a tag of its own, and "address[domains]" for a scoped copy.
func serverList(cfg *xrayConf.Config) []string {
	var out []string
	for _, ns := range cfg.DNSConfig.Servers {
		s := ns.Address.String()
		if ns.Tag != "" {
			s += "#" + ns.Tag
		}
		if len(ns.Domains) > 0 {
			s += "[" + strings.Join(ns.Domains, ",") + "]"
		}
		out = append(out, s)
	}
	return out
}

func wantServers(t *testing.T, cfg *xrayConf.Config, want ...string) {
	t.Helper()
	got := serverList(cfg)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("servers = %v, want %v", got, want)
	}
}

// wantModuleQueryRules checks the rules ApplyDNS added ahead of the tiers:
// the direct resolvers' own when withDirect, then the apps' :53. No rule
// sends the module's other queries direct.
func wantModuleQueryRules(t *testing.T, cfg *xrayConf.Config, before int, withDirect bool) {
	t.Helper()
	rules := decodeRules(t, cfg.RouterConfig.RuleList)
	added := rules[:len(rules)-before]
	if withDirect {
		if len(added) != 2 || len(added[0].InboundTag) != 1 || added[0].InboundTag[0] != dnsDirectTag || added[0].OutboundTag != directTag {
			t.Fatalf("added rules = %+v, want the direct resolvers' then the apps' :53", added)
		}
		added = added[1:]
	}
	if len(added) != 1 || added[0].Port != "53" || added[0].OutboundTag != dnsOutboundTag {
		t.Fatalf("added rules = %+v, want the apps' :53 only", added)
	}
	for _, r := range rules {
		if len(r.InboundTag) == 1 && r.InboundTag[0] == dnsInternalTag && r.OutboundTag == directTag {
			t.Fatalf("the module's queries are sent direct: %+v", r)
		}
	}
}

func appliedDNSConfig(t *testing.T, prof RoutingProfile, dns dnsconfig.Config) (*xrayConf.Config, int) {
	t.Helper()
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, prof, "warning")
	if err != nil {
		t.Fatal(err)
	}
	before := len(res.Config.RouterConfig.RuleList)
	ApplyDNS(res.Config, dns, prof)
	return res.Config, before
}

// With fake-ip on, the resolvers behind fakedns carry the direct tag where
// the module looks up only to dial direct (AsIs, or direct-all), and under a
// resolving strategy in proxy-all the general resolvers stand there alone,
// untagged. The filter's copy of the general resolver is untagged either way.
func TestApplyDNS_FakeIPModuleQueriesTravelWithTheirFlows(t *testing.T) {
	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}, DirectServers: []string{"77.88.8.8"}, FakeIPFilter: []string{"full:outside.test"}}
	proxyAll := RoutingProfile{Tiers: []routing.Tier{{Direct: []string{"domain:ru"}, Block: []string{"192.0.2.0/24"}}}}
	direct := []string{"77.88.8.8#" + dnsDirectTag, "1.1.1.1#" + dnsDirectTag}

	cfg, before := appliedDNSConfig(t, proxyAll, dns)
	wantServers(t, cfg, append([]string{"1.1.1.1[full:outside.test]", "fakedns"}, direct...)...)
	wantModuleQueryRules(t, cfg, before, true)
	if cfg.DNSConfig.Tag != dnsInternalTag {
		t.Fatalf("DNSConfig.Tag = %q, want %q", cfg.DNSConfig.Tag, dnsInternalTag)
	}

	for _, strategy := range []string{"IPIfNonMatch", "IPOnDemand"} {
		resolving := proxyAll
		resolving.DomainStrategy = strategy
		cfg, before = appliedDNSConfig(t, resolving, dns)
		wantServers(t, cfg, "1.1.1.1[full:outside.test]", "fakedns", "1.1.1.1")
		wantModuleQueryRules(t, cfg, before, false)

		directAll := RoutingProfile{Mode: ModeDirectAll, DomainStrategy: strategy, Tiers: []routing.Tier{{Proxy: []string{"domain:youtube.com"}}}}
		cfg, before = appliedDNSConfig(t, directAll, dns)
		wantServers(t, cfg, append([]string{"1.1.1.1[full:outside.test]", "fakedns"}, direct...)...)
		wantModuleQueryRules(t, cfg, before, true)
	}

	// No direct outbound: nothing is direct, so no lookup is made to dial
	// direct, and whatever the direct resolvers are asked goes as the default
	// outbound dials.
	cfg, before = appliedDNSConfig(t, RoutingProfile{}, dns)
	if hasOutbound(cfg, directTag) {
		t.Fatal("an empty profile made a direct outbound")
	}
	wantServers(t, cfg, append([]string{"1.1.1.1[full:outside.test]", "fakedns"}, direct...)...)
	wantModuleQueryRules(t, cfg, before, false)
}
