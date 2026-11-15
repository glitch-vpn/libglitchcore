package xrayconfig

import (
	"testing"

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
	wantModuleQueryRules(t, cfg, before, true)

	// A direct resolver that is also a general one is told apart: the
	// direct copy carries the tag, the general one does not.
	cfg, before = appliedDNSConfig(t, proxyAll, dnsconfig.Config{Servers: []string{"1.1.1.1"}, DirectServers: []string{"1.1.1.1"}})
	wantServers(t, cfg, "1.1.1.1#"+dnsDirectTag+"[domain:ru]", "1.1.1.1")
	wantModuleQueryRules(t, cfg, before, true)

	// Direct-all: the direct resolvers answer by default, and the proxied
	// names' copies of the general resolver keep the proxied path.
	directAll := RoutingProfile{Mode: ModeDirectAll, Tiers: []routing.Tier{{Proxy: []string{"domain:youtube.com"}}}}
	cfg, before = appliedDNSConfig(t, directAll, dnsconfig.Config{Servers: []string{"1.1.1.1"}, DirectServers: []string{"77.88.8.8"}})
	wantServers(t, cfg, "1.1.1.1[domain:youtube.com]", "77.88.8.8#"+dnsDirectTag, "1.1.1.1")
	wantModuleQueryRules(t, cfg, before, true)
}
