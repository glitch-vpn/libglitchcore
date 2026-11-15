package xrayconfig

import (
	"reflect"
	"slices"
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

// wantModuleQueryRules checks the rules ApplyDNS added ahead of the tiers,
// in order: with a direct outbound, the direct resolvers' queries to it when
// a resolver carries their tag, and the other resolvers' to it on the local
// networks; then the other resolvers' through the proxy; then the apps' :53.
func wantModuleQueryRules(t *testing.T, cfg *xrayConf.Config, before int) {
	t.Helper()
	rules := decodeRules(t, cfg.RouterConfig.RuleList)
	added := rules[:len(rules)-before]
	var want []ruleView
	if hasOutbound(cfg, directTag) {
		if slices.ContainsFunc(cfg.DNSConfig.Servers, func(ns *xrayConf.NameServerConfig) bool { return ns.Tag == dnsDirectTag }) {
			want = append(want, ruleView{InboundTag: []string{dnsDirectTag}, OutboundTag: directTag})
		}
		want = append(want, ruleView{InboundTag: []string{dnsInternalTag}, IP: routing.LocalNetworkCIDRs, OutboundTag: directTag})
	}
	want = append(want,
		ruleView{InboundTag: []string{dnsInternalTag}, OutboundTag: cfg.OutboundConfigs[0].Tag},
		ruleView{InboundTag: []string{AppTrafficTag, ForceProxyTag}, Port: "53", OutboundTag: dnsOutboundTag})
	if !reflect.DeepEqual(added, want) {
		t.Fatalf("added rules = %+v, want %+v", added, want)
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
	wantModuleQueryRules(t, cfg, before)
	if cfg.DNSConfig.Tag != dnsInternalTag {
		t.Fatalf("DNSConfig.Tag = %q, want %q", cfg.DNSConfig.Tag, dnsInternalTag)
	}

	for _, strategy := range []string{"IPIfNonMatch", "IPOnDemand"} {
		resolving := proxyAll
		resolving.DomainStrategy = strategy
		cfg, before = appliedDNSConfig(t, resolving, dns)
		wantServers(t, cfg, "1.1.1.1[full:outside.test]", "fakedns", "1.1.1.1")
		wantModuleQueryRules(t, cfg, before)

		directAll := RoutingProfile{Mode: ModeDirectAll, DomainStrategy: strategy, Tiers: []routing.Tier{{Proxy: []string{"domain:youtube.com"}}}}
		cfg, before = appliedDNSConfig(t, directAll, dns)
		wantServers(t, cfg, append([]string{"1.1.1.1[full:outside.test]", "fakedns"}, direct...)...)
		wantModuleQueryRules(t, cfg, before)
	}

	// No direct outbound: nothing is direct, so no lookup is made to dial
	// direct, and whatever the direct resolvers are asked goes as the default
	// outbound dials.
	cfg, before = appliedDNSConfig(t, RoutingProfile{}, dns)
	if hasOutbound(cfg, directTag) {
		t.Fatal("an empty profile made a direct outbound")
	}
	wantServers(t, cfg, append([]string{"1.1.1.1[full:outside.test]", "fakedns"}, direct...)...)
	wantModuleQueryRules(t, cfg, before)
}
