package xrayconfig

import (
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	xrayCore "github.com/xtls/xray-core/core"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// With fake-ip off the apps' queries are taken by the dns outbound, so the
// configured resolvers answer them, and the module's own queries travel as
// the name's flow would: a direct resolver's leave direct by the resolver's
// own tag, the others through the proxy.
func TestApplyDNS_NormalModeInterceptsAppQueries(t *testing.T) {
	proxyAll := RoutingProfile{Tiers: []routing.Tier{{Direct: []string{"domain:ru"}}}}
	cfg, before := appliedDNSConfig(t, proxyAll, dnsconfig.Config{Servers: []string{"1.1.1.1"}, DirectServers: []string{"77.88.8.8", "https://dns.yandex/dns-query"}})
	if !hasOutbound(cfg, dnsOutboundTag) {
		t.Fatal("no dns outbound")
	}
	if cfg.DNSConfig.Tag != dnsInternalTag {
		t.Fatalf("DNSConfig.Tag = %q, want %q", cfg.DNSConfig.Tag, dnsInternalTag)
	}
	wantServers(t, cfg, "77.88.8.8#"+dnsDirectTag+"[domain:ru]", "https://dns.yandex/dns-query#"+dnsDirectTag+"[domain:ru]", "1.1.1.1")
	wantModuleQueryRules(t, cfg, before)

	// A direct resolver that is also a general one is told apart: the
	// direct copy carries the tag, the general one does not.
	cfg, before = appliedDNSConfig(t, proxyAll, dnsconfig.Config{Servers: []string{"1.1.1.1"}, DirectServers: []string{"1.1.1.1"}})
	wantServers(t, cfg, "1.1.1.1#"+dnsDirectTag+"[domain:ru]", "1.1.1.1")
	wantModuleQueryRules(t, cfg, before)

	// Direct-all: the direct resolvers answer by default, and the proxied
	// names' copies of the general resolver keep the proxied path.
	directAll := RoutingProfile{Mode: ModeDirectAll, Tiers: []routing.Tier{{Proxy: []string{"domain:youtube.com"}}}}
	cfg, before = appliedDNSConfig(t, directAll, dnsconfig.Config{Servers: []string{"1.1.1.1"}, DirectServers: []string{"77.88.8.8"}})
	wantServers(t, cfg, "1.1.1.1[domain:youtube.com]", "77.88.8.8#"+dnsDirectTag, "1.1.1.1")
	wantModuleQueryRules(t, cfg, before)
}

// A tier holding a resolver's address does not decide where that resolver's
// queries go: the direct resolvers' leave direct, the others' through the
// proxy, and a resolver on the local networks is reached direct by either.
func TestApplyDNS_ResolverQueriesIgnoreTheTiers(t *testing.T) {
	prof := RoutingProfile{Tiers: []routing.Tier{{Direct: []string{"9.9.9.9/32", "domain:ru"}}}}
	for _, dns := range []dnsconfig.Config{
		{Servers: []string{"9.9.9.9"}, DirectServers: []string{"77.88.8.8"}},
		{Mode: dnsconfig.ModeFakeIP, Servers: []string{"9.9.9.9"}, DirectServers: []string{"77.88.8.8"}, FakeIPFilter: []string{"full:outside.test"}},
	} {
		res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, prof, "none")
		if err != nil {
			t.Fatal(err)
		}
		ApplyDNS(res.Config, dns, prof)
		built, err := res.Config.Build()
		if err != nil {
			t.Fatal(err)
		}
		inst, err := xrayCore.New(built)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			inbound, address string
			port             uint16
			want             string
		}{
			{dnsInternalTag, "9.9.9.9", 53, res.RouteTarget},
			{dnsInternalTag, "192.168.1.1", 53, directTag},
			{dnsDirectTag, "77.88.8.8", 53, directTag},
			{AppTrafficTag, "9.9.9.9", 443, tierDirectTag(0)},
		} {
			got, err := pickRoute(inst, c.inbound, xnet.UDPDestination(xnet.ParseAddress(c.address), xnet.Port(c.port)), "")
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("mode %q: a query from %s to %s -> %s, want %s", dns.Mode, c.inbound, c.address, got, c.want)
			}
		}
	}
}
