package xrayconfig

import (
	"encoding/json"
	"strings"
	"testing"

	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

const dnsTestLink = "vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=tcp&security=tls&sni=a.example.com"

func TestApplyDNS_TranslatesAndSkipsDoT(t *testing.T) {
	cfg := &xrayConf.Config{}
	ApplyDNS(cfg, dnsconfig.Config{Servers: []string{
		"1.1.1.1",                      // plain UDP -> kept
		"https://dns.google/dns-query", // DoH -> kept
		"quic://dns.adguard.com",       // DoQ -> quic+local://
		"tls://1.1.1.1",                // DoT -> skipped (xray has none)
	}}, RoutingProfile{})

	if cfg.DNSConfig == nil {
		t.Fatal("DNSConfig not set")
	}
	var got []string
	for _, ns := range cfg.DNSConfig.Servers {
		got = append(got, ns.Address.String())
	}

	want := []string{"1.1.1.1", "https://dns.google/dns-query", "quic+local://dns.adguard.com"}
	if len(got) != len(want) {
		t.Fatalf("servers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("server[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestApplyDNS_EmptyIsNoop(t *testing.T) {
	cfg := &xrayConf.Config{}
	ApplyDNS(cfg, dnsconfig.Config{}, RoutingProfile{})
	if cfg.DNSConfig != nil {
		t.Fatalf("expected no DNSConfig for empty input, got %+v", cfg.DNSConfig)
	}
}

func TestApplyDNS_FakeIPWiring(t *testing.T) {
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, RoutingProfile{}, "warning")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	cfg := res.Config
	beforeRules := len(cfg.RouterConfig.RuleList)

	ApplyDNS(cfg, dnsconfig.Config{
		Mode:         dnsconfig.ModeFakeIP,
		Servers:      []string{"1.1.1.1"},
		FakeIPFilter: []string{"domain:lan", "full:router.local"},
	}, RoutingProfile{})

	if cfg.FakeDNS == nil {
		t.Fatal("FakeDNS pool not set")
	}
	if b, mErr := json.Marshal(cfg.FakeDNS); mErr != nil {
		t.Fatalf("FakeDNS marshal: %v", mErr)
	} else if !strings.Contains(string(b), fakeIPv4Pool) || !strings.Contains(string(b), fakeIPv6Pool) {
		t.Fatalf("FakeDNS pools = %s, want v4 %s + v6 %s", b, fakeIPv4Pool, fakeIPv6Pool)
	}

	// Server list: [exclude(1.1.1.1 w/ filter domains), fakedns, 1.1.1.1].
	var addrs []string
	var excludeHasDomains bool
	for _, ns := range cfg.DNSConfig.Servers {
		addrs = append(addrs, ns.Address.String())
		if len(ns.Domains) > 0 {
			excludeHasDomains = true
		}
	}
	if !excludeHasDomains {
		t.Fatalf("no exclude resolver carrying the fake-ip filter domains; servers=%v", addrs)
	}
	foundFake := false
	for _, a := range addrs {
		if a == "fakedns" {
			foundFake = true
		}
	}
	if !foundFake {
		t.Fatalf("no fakedns server in %v", addrs)
	}

	foundDNSOut := false
	for _, ob := range cfg.OutboundConfigs {
		if ob.Tag == dnsOutboundTag && ob.Protocol == "dns" {
			foundDNSOut = true
		}
	}
	if !foundDNSOut {
		t.Fatal("no dns outbound")
	}

	if len(cfg.RouterConfig.RuleList) != beforeRules+1 {
		t.Fatalf("rule count = %d, want %d", len(cfg.RouterConfig.RuleList), beforeRules+1)
	}
	var first struct {
		Port        string   `json:"port"`
		InboundTag  []string `json:"inboundTag"`
		OutboundTag string   `json:"outboundTag"`
	}
	if uErr := json.Unmarshal(cfg.RouterConfig.RuleList[0], &first); uErr != nil {
		t.Fatalf("first rule unmarshal: %v", uErr)
	}
	if first.Port != "53" || first.OutboundTag != dnsOutboundTag {
		t.Fatalf("first rule = %+v, want port 53 -> %s", first, dnsOutboundTag)
	}
	if len(first.InboundTag) == 0 || first.InboundTag[0] != "tun2socks" {
		t.Fatalf("first rule inboundTag = %v, want app inbounds", first.InboundTag)
	}
	if cfg.DNSConfig.Tag != dnsInternalTag {
		t.Fatalf("DNSConfig.Tag = %q, want %q", cfg.DNSConfig.Tag, dnsInternalTag)
	}
}

func TestApplyDNS_FakeIPInternalQueriesGoDirect(t *testing.T) {
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, RoutingProfile{Mode: "direct-all"}, "warning")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	cfg := res.Config
	if !hasOutbound(cfg, directTag) {
		t.Fatal("direct-all profile did not create the direct outbound")
	}

	ApplyDNS(cfg, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}, RoutingProfile{})

	if cfg.DNSConfig.Tag != dnsInternalTag {
		t.Fatalf("DNSConfig.Tag = %q, want %q", cfg.DNSConfig.Tag, dnsInternalTag)
	}
	type ruleView struct {
		Port        string   `json:"port"`
		InboundTag  []string `json:"inboundTag"`
		OutboundTag string   `json:"outboundTag"`
	}
	var first, second ruleView
	if uErr := json.Unmarshal(cfg.RouterConfig.RuleList[0], &first); uErr != nil {
		t.Fatalf("first rule unmarshal: %v", uErr)
	}
	if uErr := json.Unmarshal(cfg.RouterConfig.RuleList[1], &second); uErr != nil {
		t.Fatalf("second rule unmarshal: %v", uErr)
	}
	if len(first.InboundTag) != 1 || first.InboundTag[0] != dnsInternalTag || first.OutboundTag != directTag {
		t.Fatalf("first rule = %+v, want inbound %s -> %s", first, dnsInternalTag, directTag)
	}
	if second.Port != "53" || second.OutboundTag != dnsOutboundTag {
		t.Fatalf("second rule = %+v, want port 53 -> %s", second, dnsOutboundTag)
	}
}

func TestApplyDNS_FakeIPBuilds(t *testing.T) {
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, RoutingProfile{}, "warning")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	cfg := res.Config
	ApplyDNS(cfg, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}, RoutingProfile{})
	if _, _, err := ApplyLocalSocksInbound(cfg); err != nil {
		t.Fatalf("ApplyLocalSocksInbound: %v", err)
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("cfg.Build() with fakedns failed: %v", err)
	}
}

func TestApplyDNS_DisableIPv6(t *testing.T) {
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, RoutingProfile{}, "warning")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	cfg := res.Config
	ApplyDNS(cfg, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}, DisableIPv6: true}, RoutingProfile{})

	if b, mErr := json.Marshal(cfg.FakeDNS); mErr != nil {
		t.Fatalf("FakeDNS marshal: %v", mErr)
	} else if !strings.Contains(string(b), fakeIPv4Pool) || strings.Contains(string(b), fakeIPv6Pool) {
		t.Fatalf("FakeDNS pools = %s, want v4-only (%s)", b, fakeIPv4Pool)
	}
	if cfg.DNSConfig.QueryStrategy != "UseIPv4" {
		t.Fatalf("fake-ip QueryStrategy = %q, want UseIPv4", cfg.DNSConfig.QueryStrategy)
	}
	if _, _, err := ApplyLocalSocksInbound(cfg); err != nil {
		t.Fatalf("ApplyLocalSocksInbound: %v", err)
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("cfg.Build() with v4-only fake pool failed: %v", err)
	}

	plain := &xrayConf.Config{}
	ApplyDNS(plain, dnsconfig.Config{Servers: []string{"1.1.1.1"}, DisableIPv6: true}, RoutingProfile{})
	if plain.DNSConfig.QueryStrategy != "UseIPv4" {
		t.Fatalf("normal QueryStrategy = %q, want UseIPv4", plain.DNSConfig.QueryStrategy)
	}

	// No servers at all: AAAA suppression must still reach xray's resolver.
	empty := &xrayConf.Config{}
	ApplyDNS(empty, dnsconfig.Config{DisableIPv6: true}, RoutingProfile{})
	if empty.DNSConfig == nil || empty.DNSConfig.QueryStrategy != "UseIPv4" {
		t.Fatalf("empty-server DNSConfig = %+v, want UseIPv4", empty.DNSConfig)
	}
}

func TestApplyDNS_Hosts(t *testing.T) {
	hosts := map[string][]string{
		"doh.example":        {"1.2.3.4", "5.6.7.8"},
		"domain:corp.local":  {"10.0.0.53"},
		"regexp:.*\\.ad\\.":  {"127.0.0.1"},
		"keyword:tracker":    {"127.0.0.1"},
		"geosite:category-x": {"127.0.0.1"},
	}

	// Plain mode; a hosts-only config (no servers) must still materialize.
	plain := &xrayConf.Config{}
	ApplyDNS(plain, dnsconfig.Config{Hosts: hosts}, RoutingProfile{})
	if plain.DNSConfig == nil || plain.DNSConfig.Hosts == nil {
		t.Fatalf("hosts-only DNSConfig = %+v", plain.DNSConfig)
	}

	// Fake-ip mode: hosts ride the same DNSConfig; the full config builds.
	// geosite: keys need geosite.dat at build time, so only prefix-free and
	// domain:/regexp:/keyword: keys go through the build check.
	buildable := map[string][]string{
		"doh.example":       {"1.2.3.4", "5.6.7.8"},
		"domain:corp.local": {"10.0.0.53"},
	}
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, RoutingProfile{}, "warning")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	cfg := res.Config
	ApplyDNS(cfg, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}, Hosts: buildable}, RoutingProfile{})
	if cfg.DNSConfig.Hosts == nil {
		t.Fatal("fake-ip DNSConfig.Hosts not set")
	}
	b, err := json.Marshal(cfg.DNSConfig.Hosts)
	if err != nil {
		t.Fatalf("hosts marshal: %v", err)
	}
	for _, want := range []string{"doh.example", "1.2.3.4", "domain:corp.local"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("hosts %s missing %q", b, want)
		}
	}
	if _, _, err := ApplyLocalSocksInbound(cfg); err != nil {
		t.Fatalf("ApplyLocalSocksInbound: %v", err)
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("cfg.Build() with hosts failed: %v", err)
	}
}

func TestApplyDNS_DirectServers_Normal(t *testing.T) {
	// Tier 1 proxies vk.ru; tier 2 sends the whole .ru zone direct. Per-server
	// scopes are flat, so without the proxy-scoped copy first, vk.ru would be
	// pinned to the direct resolver while its traffic goes to the proxy.
	prof := RoutingProfile{Tiers: []routing.Tier{
		{Proxy: []string{"domain:vk.ru"}},
		{Direct: []string{"geoip:ru", "10.0.0.0/8", "domain:ru", "full:bank.local"}},
	}}
	cfg := &xrayConf.Config{}
	ApplyDNS(cfg, dnsconfig.Config{
		Servers:       []string{"1.1.1.1"},
		DirectServers: []string{"77.88.8.8"},
	}, prof)

	servers := cfg.DNSConfig.Servers
	if len(servers) != 3 {
		t.Fatalf("want [general(proxy-scoped), direct(direct-scoped), general], got %+v", servers)
	}
	proxyScoped := servers[0]
	if proxyScoped.Address.String() != "1.1.1.1" || !proxyScoped.SkipFallback ||
		len(proxyScoped.Domains) != 1 || proxyScoped.Domains[0] != "domain:vk.ru" {
		t.Fatalf("proxy-scoped general server = %+v", proxyScoped)
	}
	direct := servers[1]
	if direct.Address.String() != "77.88.8.8" || !direct.SkipFallback {
		t.Fatalf("direct server = %+v, want 77.88.8.8 with SkipFallback", direct)
	}
	// Scope comes from direct domain matchers across all tiers; geoip and
	// bare IPs carry no name scope.
	wantDomains := []string{"domain:ru", "full:bank.local"}
	if len(direct.Domains) != len(wantDomains) {
		t.Fatalf("direct domains = %v, want %v", direct.Domains, wantDomains)
	}
	for i := range wantDomains {
		if direct.Domains[i] != wantDomains[i] {
			t.Fatalf("direct domains = %v, want %v", direct.Domains, wantDomains)
		}
	}
	// The unscoped tail keeps names resolvable when the direct resolver is
	// unreachable, and serves everything neither scope claims.
	if tail := servers[2]; tail.Address.String() != "1.1.1.1" ||
		len(tail.Domains) != 0 || tail.SkipFallback {
		t.Fatalf("general tail = %+v", tail)
	}
}

func TestApplyDNS_DirectServers_FakeIP(t *testing.T) {
	// fake-ip needs no domain rules: the app keeps getting fake IPs and the
	// module's own lookups (what freedom does when it dials a direct-routed
	// name) skip fakedns and land on the direct resolvers - mihomo's
	// direct-nameserver reach. The direct rule here is IP-only on purpose
	// (a CIDR, not geoip:, so cfg.Build() needs no geoip.dat).
	prof := RoutingProfile{Tiers: []routing.Tier{{Direct: []string{"10.0.0.0/8"}}}}
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, prof, "warning")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	cfg := res.Config
	ApplyDNS(cfg, dnsconfig.Config{
		Mode:          dnsconfig.ModeFakeIP,
		Servers:       []string{"1.1.1.1"},
		FakeIPFilter:  []string{"domain:lan"},
		DirectServers: []string{"77.88.8.8"},
	}, prof)

	// Order: [filter exclude, fakedns, direct, general].
	var addrs []string
	for _, ns := range cfg.DNSConfig.Servers {
		addrs = append(addrs, ns.Address.String())
	}
	want := []string{"1.1.1.1", "fakedns", "77.88.8.8", "1.1.1.1"}
	if len(addrs) != len(want) {
		t.Fatalf("servers = %v, want %v", addrs, want)
	}
	for i := range want {
		if addrs[i] != want[i] {
			t.Fatalf("servers = %v, want %v", addrs, want)
		}
	}
	// Without SkipFallback the exclusion copy answers every name ahead of
	// fakedns: fake-ip stops handing out fake IPs and the direct resolvers
	// below it are never reached.
	if excl := cfg.DNSConfig.Servers[0]; !excl.SkipFallback || len(excl.Domains) == 0 {
		t.Fatalf("fake-ip filter server must be scoped and skip fallback: %+v", excl)
	}
	if direct := cfg.DNSConfig.Servers[2]; len(direct.Domains) != 0 || direct.SkipFallback {
		t.Fatalf("direct server must stay unscoped and fallback-able: %+v", direct)
	}
	if _, _, err := ApplyLocalSocksInbound(cfg); err != nil {
		t.Fatalf("ApplyLocalSocksInbound: %v", err)
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("cfg.Build() with direct servers failed: %v", err)
	}
}

func TestApplyDNS_DirectServers_NormalDirectAll(t *testing.T) {
	// direct-all: the catch-all is direct, so the direct resolvers answer by
	// default and the general list is scoped to the explicit proxy rules.
	prof := RoutingProfile{
		Mode:  ModeDirectAll,
		Tiers: []routing.Tier{{Proxy: []string{"domain:youtube.com"}}},
	}
	cfg := &xrayConf.Config{}
	ApplyDNS(cfg, dnsconfig.Config{
		Servers:       []string{"1.1.1.1"},
		DirectServers: []string{"77.88.8.8"},
	}, prof)

	servers := cfg.DNSConfig.Servers
	if len(servers) != 3 {
		t.Fatalf("servers = %+v, want [general(proxy-scoped), direct, general]", servers)
	}
	if servers[0].Address.String() != "1.1.1.1" || !servers[0].SkipFallback ||
		len(servers[0].Domains) != 1 || servers[0].Domains[0] != "domain:youtube.com" {
		t.Fatalf("general resolver must be scoped to the proxy rules: %+v", servers[0])
	}
	if servers[1].Address.String() != "77.88.8.8" || len(servers[1].Domains) != 0 {
		t.Fatalf("direct resolver must be the unscoped default: %+v", servers[1])
	}
	if tail := servers[2]; tail.Address.String() != "1.1.1.1" ||
		len(tail.Domains) != 0 || tail.SkipFallback {
		t.Fatalf("general tail keeps names resolvable if the direct resolver dies: %+v", tail)
	}
}

func TestApplyDNS_DirectServers_NoDirectDomains(t *testing.T) {
	// Normal mode has no fakedns to fall through, so the split relies on
	// domain scopes: direct rules without a name component leave nothing to
	// scope and the resolvers are dropped rather than answering everything.
	prof := RoutingProfile{Tiers: []routing.Tier{{Direct: []string{"geoip:ru", "10.0.0.0/8"}}}}
	cfg := &xrayConf.Config{}
	ApplyDNS(cfg, dnsconfig.Config{
		Servers:       []string{"1.1.1.1"},
		DirectServers: []string{"77.88.8.8"},
	}, prof)
	servers := cfg.DNSConfig.Servers
	if len(servers) != 1 || servers[0].Address.String() != "1.1.1.1" {
		t.Fatalf("servers = %+v, want only the general resolver", servers)
	}
}

func TestSniffing_FakednsHarmlessWithoutPool(t *testing.T) {
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, RoutingProfile{}, "warning")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	cfg := res.Config
	ApplyDNS(cfg, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, RoutingProfile{}) // normal mode, no pool
	if _, _, err := ApplyLocalSocksInbound(cfg); err != nil {
		t.Fatalf("ApplyLocalSocksInbound: %v", err)
	}
	if cfg.FakeDNS != nil {
		t.Fatal("normal mode must not set a fake pool")
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("cfg.Build() (normal, fakedns sniffer inert) failed: %v", err)
	}
}
