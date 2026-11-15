package xrayconfig

import (
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// With fake-ip off the apps' queries are taken by the dns outbound, so the
// configured resolvers answer them, and of the module's own queries only
// those to the direct resolvers' addresses are dialed direct, in either
// mode: the others travel through the proxy.
func TestApplyDNS_NormalModeInterceptsAppQueries(t *testing.T) {
	proxyAll := RoutingProfile{Tiers: []routing.Tier{{Direct: []string{"domain:ru"}}}}
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, proxyAll, "warning")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	cfg := res.Config
	if !hasOutbound(cfg, directTag) {
		t.Fatal("a direct tier did not create the direct outbound")
	}
	before := len(cfg.RouterConfig.RuleList)
	ApplyDNS(cfg, dnsconfig.Config{Servers: []string{"1.1.1.1"}, DirectServers: []string{"77.88.8.8", "https://dns.yandex/dns-query"}}, proxyAll)
	if !hasOutbound(cfg, dnsOutboundTag) {
		t.Fatal("no dns outbound")
	}
	if cfg.DNSConfig.Tag != dnsInternalTag {
		t.Fatalf("DNSConfig.Tag = %q, want %q", cfg.DNSConfig.Tag, dnsInternalTag)
	}
	if n := len(cfg.RouterConfig.RuleList); n != before+3 {
		t.Fatalf("%d rules, want %d: the direct resolvers by address and by name, then the apps' :53", n, before+3)
	}
	rules := decodeRules(t, cfg.RouterConfig.RuleList)
	byAddress, byName, apps := rules[0], rules[1], rules[2]
	if len(byAddress.InboundTag) != 1 || byAddress.InboundTag[0] != dnsInternalTag || byAddress.OutboundTag != directTag ||
		len(byAddress.IP) != 1 || byAddress.IP[0] != "77.88.8.8" {
		t.Fatalf("direct resolver by address = %+v", byAddress)
	}
	if len(byName.InboundTag) != 1 || byName.InboundTag[0] != dnsInternalTag || byName.OutboundTag != directTag ||
		len(byName.Domain) != 1 || byName.Domain[0] != "full:dns.yandex" {
		t.Fatalf("direct resolver by name = %+v", byName)
	}
	if apps.Port != "53" || apps.OutboundTag != dnsOutboundTag || len(apps.InboundTag) == 0 || apps.InboundTag[0] != AppTrafficTag {
		t.Fatalf("apps' :53 rule = %+v, want port 53 -> %s", apps, dnsOutboundTag)
	}

	// A direct resolver that is also a general one cannot be told apart by
	// its address: it stays on the proxied path rather than carry every
	// query direct.
	res, err = BuildConfig([]string{dnsTestLink}, BalancerOptions{}, proxyAll, "warning")
	if err != nil {
		t.Fatal(err)
	}
	cfg = res.Config
	before = len(cfg.RouterConfig.RuleList)
	ApplyDNS(cfg, dnsconfig.Config{Servers: []string{"1.1.1.1"}, DirectServers: []string{"1.1.1.1"}}, proxyAll)
	if n := len(cfg.RouterConfig.RuleList); n != before+1 {
		t.Fatalf("%d rules, want %d: the apps' :53 only", n, before+1)
	}
	if apps := decodeRules(t, cfg.RouterConfig.RuleList)[0]; apps.Port != "53" || apps.OutboundTag != dnsOutboundTag {
		t.Fatalf("apps' :53 rule = %+v", apps)
	}

	// Direct-all: the direct resolvers are the default, so most queries go
	// direct by address; the proxied names' copies of the general resolver
	// keep the proxied path.
	directAll := RoutingProfile{Mode: ModeDirectAll, Tiers: []routing.Tier{{Proxy: []string{"domain:youtube.com"}}}}
	res, err = BuildConfig([]string{dnsTestLink}, BalancerOptions{}, directAll, "warning")
	if err != nil {
		t.Fatal(err)
	}
	cfg = res.Config
	before = len(cfg.RouterConfig.RuleList)
	ApplyDNS(cfg, dnsconfig.Config{Servers: []string{"1.1.1.1"}, DirectServers: []string{"77.88.8.8"}}, directAll)
	if n := len(cfg.RouterConfig.RuleList); n != before+2 {
		t.Fatalf("%d rules, want %d: the direct resolver by address, then the apps' :53", n, before+2)
	}
	rules = decodeRules(t, cfg.RouterConfig.RuleList)
	if byAddress := rules[0]; len(byAddress.InboundTag) != 1 || byAddress.InboundTag[0] != dnsInternalTag ||
		byAddress.OutboundTag != directTag || len(byAddress.IP) != 1 || byAddress.IP[0] != "77.88.8.8" {
		t.Fatalf("direct resolver by address = %+v", byAddress)
	}
	if apps := rules[1]; apps.Port != "53" || apps.OutboundTag != dnsOutboundTag {
		t.Fatalf("apps' :53 rule = %+v", apps)
	}
}
