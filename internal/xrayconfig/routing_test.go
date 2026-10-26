package xrayconfig

import (
	"encoding/json"
	"testing"

	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

type ruleView struct {
	OutboundTag string   `json:"outboundTag"`
	BalancerTag string   `json:"balancerTag"`
	InboundTag  []string `json:"inboundTag"`
	Domain      []string `json:"domain"`
	IP          []string `json:"ip"`
	Port        string   `json:"port"`
	Network     string   `json:"network"`
	Process     []string `json:"process"`
}

func applyTo(t *testing.T, p RoutingProfile, proxyTag string, isBalancer bool) (*xrayConf.Config, []ruleView) {
	t.Helper()
	cfg := &xrayConf.Config{
		OutboundConfigs: []xrayConf.OutboundDetourConfig{{Protocol: "freedom", Tag: proxyTag}},
	}
	applyRouting(p, cfg, proxyTag, isBalancer)
	var views []ruleView
	for _, raw := range cfg.RouterConfig.RuleList {
		var v ruleView
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("rule not JSON: %v (%s)", err, raw)
		}
		views = append(views, v)
	}
	return cfg, views
}

func TestApply_ProxyAllDefault(t *testing.T) {
	cfg, rules := applyTo(t, RoutingProfile{}, "proxy", false)
	if len(rules) != 2 {
		t.Fatalf("default profile: want the exit-echo rule and the catch-all, got %d: %+v", len(rules), rules)
	}
	r := rules[1]
	if r.OutboundTag != "proxy" || len(r.InboundTag) != 1 || r.InboundTag[0] != AppTrafficTag {
		t.Fatalf("catch-all = %+v, want tun2socks->proxy", r)
	}
	if hasOutbound(cfg, directTag) || hasOutbound(cfg, blockTag) {
		t.Error("default profile must not add direct/block outbounds")
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("xray rejected default routing: %v", err)
	}
}

func TestApply_ProxyAll_BlockDirectLocalOrder(t *testing.T) {
	p := RoutingProfile{
		Mode:          ModeProxyAll,
		Tiers:         []routing.Tier{{Block: []string{"ads.example"}, Direct: []string{"domain:bank.example"}}},
		LocalNetworks: true,
	}
	cfg, rules := applyTo(t, p, "proxy", false)

	// Bare "ads.example" -> domain suffix; "domain:bank.example" -> same syntax.
	if rules[1].OutboundTag != blockTag || rules[1].Domain[0] != "domain:ads.example" {
		t.Errorf("first tier rule must be block: %+v", rules[1])
	}
	last := rules[len(rules)-1]
	if last.OutboundTag != "proxy" || len(last.InboundTag) == 0 {
		t.Errorf("last rule must be tun2socks->proxy catch-all: %+v", last)
	}
	if !hasOutbound(cfg, directTag) || !hasOutbound(cfg, blockTag) {
		t.Error("direct + block outbounds must be present")
	}
	foundLocal := false
	for _, r := range rules {
		if r.OutboundTag == directTag {
			for _, ip := range r.IP {
				if ip == "10.0.0.0/8" {
					foundLocal = true
				}
			}
		}
	}
	if !foundLocal {
		t.Error("local networks direct rule missing")
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("xray rejected proxy-all routing: %v", err)
	}
}

func TestApply_DirectAll_CatchAllIsDirect(t *testing.T) {
	p := RoutingProfile{
		Mode:  ModeDirectAll,
		Tiers: []routing.Tier{{Proxy: []string{"domain:youtube.com"}}},
	}
	cfg, rules := applyTo(t, p, "proxy", false)

	last := rules[len(rules)-1]
	if last.OutboundTag != directTag || len(last.InboundTag) == 0 {
		t.Errorf("direct-all catch-all must be tun2socks->direct: %+v", last)
	}
	foundProxyRule := false
	for _, r := range rules {
		if r.OutboundTag == "proxy" {
			for _, d := range r.Domain {
				if d == "domain:youtube.com" {
					foundProxyRule = true
				}
			}
		}
	}
	if !foundProxyRule {
		t.Error("direct-all: proxy-domain rule missing")
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("xray rejected direct-all routing: %v", err)
	}
}

func TestApply_BalancerTargetAndProcess(t *testing.T) {
	p := RoutingProfile{
		Mode:  ModeProxyAll,
		Tiers: []routing.Tier{{Direct: []string{"process:Discord.exe"}}},
	}
	_, rules := applyTo(t, p, "vpn", true)

	last := rules[len(rules)-1]
	if last.BalancerTag != "vpn" {
		t.Errorf("catch-all must target balancerTag vpn: %+v", last)
	}
	foundProc := false
	for _, r := range rules {
		if len(r.Process) == 1 && r.Process[0] == "Discord.exe" && r.OutboundTag == directTag {
			foundProc = true
		}
	}
	if !foundProc {
		t.Error("per-process direct rule missing")
	}
}

func TestApply_ForceProxyInbound(t *testing.T) {
	p := RoutingProfile{
		Mode:  ModeDirectAll,
		Tiers: []routing.Tier{{Proxy: []string{"process:torrent.exe"}}},
	}
	_, rules := applyTo(t, p, "proxy", false)

	var forceRule, catchAll *ruleView
	for i := range rules {
		for _, tag := range rules[i].InboundTag {
			if tag == ForceProxyTag {
				forceRule = &rules[i]
			}
			if tag == AppTrafficTag {
				catchAll = &rules[i]
			}
		}
	}
	if forceRule == nil || forceRule.OutboundTag != "proxy" {
		t.Fatalf("forceproxy inbound must route to proxy, got %+v", forceRule)
	}
	if catchAll == nil || catchAll.OutboundTag != directTag {
		t.Fatalf("direct-all catch-all must be direct, got %+v", catchAll)
	}

	// No process->proxy -> no forceproxy rule (keeps the common case lean).
	_, plain := applyTo(t, RoutingProfile{Tiers: []routing.Tier{{Direct: []string{"process:App.exe"}}}}, "proxy", false)
	for _, r := range plain {
		for _, tag := range r.InboundTag {
			if tag == ForceProxyTag {
				t.Fatalf("forceproxy rule must not appear without a process->proxy rule")
			}
		}
	}
}

func TestApply_ExitEchoPrecedesTiers(t *testing.T) {
	p := RoutingProfile{
		Mode:  ModeDirectAll,
		Tiers: []routing.Tier{{Block: []string{"domain:ipify.org"}, Direct: []string{"0.0.0.0/0"}}},
	}
	_, rules := applyTo(t, p, "proxy", false)
	if len(rules) == 0 || len(rules[0].InboundTag) != 1 || rules[0].InboundTag[0] != ExitEchoTag || rules[0].OutboundTag != "proxy" {
		t.Fatalf("first rule must send the exit echo to the proxy: %+v", rules)
	}
}

func TestApply_DisableIPv6AndUDP(t *testing.T) {
	p := RoutingProfile{
		Tiers:       []routing.Tier{{Block: []string{"ads.example"}}},
		DisableIPv6: true,
		DisableUDP:  true,
	}
	cfg, rules := applyTo(t, p, "proxy", false)

	if len(rules[0].IP) != 1 || rules[0].IP[0] != "::/0" || rules[0].OutboundTag != blockTag {
		t.Fatalf("first rule must block ::/0: %+v", rules[0])
	}
	if rules[1].Network != "udp" || rules[1].Port != "1-52,54-65535" || rules[1].OutboundTag != blockTag {
		t.Fatalf("second rule must block udp except :53: %+v", rules[1])
	}
	if len(rules[2].InboundTag) != 1 || rules[2].InboundTag[0] != ExitEchoTag {
		t.Fatalf("the exit-echo rule must follow the kill-switches: %+v", rules[2])
	}
	if len(rules[3].Domain) != 1 || rules[3].Domain[0] != "domain:ads.example" {
		t.Fatalf("explicit block matchers must follow the exit-echo rule: %+v", rules[3])
	}
	if !hasOutbound(cfg, blockTag) {
		t.Fatal("blackhole outbound missing")
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("xray rejected disable rules: %v", err)
	}

	// Either flag alone still forces the blackhole outbound.
	cfg, _ = applyTo(t, RoutingProfile{DisableUDP: true}, "proxy", false)
	if !hasOutbound(cfg, blockTag) {
		t.Fatal("DisableUDP alone must add the blackhole outbound")
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("xray rejected DisableUDP-only rules: %v", err)
	}
}

func TestApply_TwoTierOrdering(t *testing.T) {
	// A more specific rule in an earlier tier must outrank a later tier even
	// when its outcome (proxy) would lose under the old block->direct->proxy
	// flattening: vk.ru->proxy (tier 1) wins over the .ru->direct suffix (tier 2).
	p := RoutingProfile{
		Mode: ModeProxyAll,
		Tiers: []routing.Tier{
			{Proxy: []string{"domain:vk.ru"}},
			{Direct: []string{"domain:ru"}},
		},
	}
	cfg, rules := applyTo(t, p, "proxy", false)

	proxyIdx, directIdx := -1, -1
	for i, r := range rules {
		for _, d := range r.Domain {
			if d == "domain:vk.ru" && r.OutboundTag == "proxy" {
				proxyIdx = i
			}
			if d == "domain:ru" && r.OutboundTag == directTag {
				directIdx = i
			}
		}
	}
	if proxyIdx == -1 || directIdx == -1 {
		t.Fatalf("missing tier rules: %+v", rules)
	}
	if proxyIdx >= directIdx {
		t.Errorf("tier 1 proxy rule (%d) must precede tier 2 direct rule (%d)", proxyIdx, directIdx)
	}
	last := rules[len(rules)-1]
	if len(last.InboundTag) == 0 || last.InboundTag[0] != AppTrafficTag {
		t.Errorf("catch-all must stay last: %+v", last)
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("xray rejected tiered routing: %v", err)
	}
}

func TestNormalizeDomainStrategy(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", true},
		{"asis", "AsIs", true},
		{"AsIs", "AsIs", true},
		{"IPIfNonMatch", "IPIfNonMatch", true},
		{" ipondemand ", "IPOnDemand", true},
		{"useip", "", false},
		{"bogus", "", false},
	}
	for _, c := range cases {
		got, ok := NormalizeDomainStrategy(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("NormalizeDomainStrategy(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestApply_DomainStrategy(t *testing.T) {
	cfg, _ := applyTo(t, RoutingProfile{DomainStrategy: "IPIfNonMatch"}, "proxy", false)
	if cfg.RouterConfig.DomainStrategy == nil || *cfg.RouterConfig.DomainStrategy != "IPIfNonMatch" {
		t.Fatalf("DomainStrategy = %v, want IPIfNonMatch", cfg.RouterConfig.DomainStrategy)
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("xray rejected domainStrategy config: %v", err)
	}

	// Unset keeps the router config byte-identical (nil -> engine default AsIs).
	cfg, _ = applyTo(t, RoutingProfile{}, "proxy", false)
	if cfg.RouterConfig.DomainStrategy != nil {
		t.Fatalf("empty profile must leave DomainStrategy nil, got %q", *cfg.RouterConfig.DomainStrategy)
	}
}

func TestMatcherRules_Classification(t *testing.T) {
	p := RoutingProfile{
		Mode: ModeProxyAll,
		Tiers: []routing.Tier{{Direct: []string{
			"geosite:category-ru", "geoip:ru", "domain:рф", "full:exact.example",
			"keyword:ads", "regexp:.*\\.cn$", "48.123.243.123", "10.0.0.0/8",
			"geosite:geolocation-!cn", "geosite:cn@ads", "geoip:!ru",
			"domain:.ru.", // zone dots stripped -> domain:ru
			"geoip:рф",    // invalid geo code -> dropped
		}}},
	}
	_, rules := applyTo(t, p, "proxy", false)

	var domains, ips []string
	for _, r := range rules {
		if r.OutboundTag == directTag {
			domains = append(domains, r.Domain...)
			ips = append(ips, r.IP...)
		}
	}
	wantDomain := map[string]bool{
		"geosite:category-ru": true, "domain:рф": true,
		"full:exact.example": true, "ads": true, "regexp:.*\\.cn$": true,
		"geosite:geolocation-!cn": true, "geosite:cn@ads": true,
		"domain:ru": true,
	}
	for _, d := range domains {
		if !wantDomain[d] {
			t.Errorf("unexpected domain matcher %q", d)
		}
		delete(wantDomain, d)
	}
	if len(wantDomain) != 0 {
		t.Errorf("missing domain matchers: %v", wantDomain)
	}
	wantIP := map[string]bool{
		"geoip:ru": true, "48.123.243.123": true, "10.0.0.0/8": true,
		"geoip:!ru": true,
	}
	for _, ip := range ips {
		if !wantIP[ip] {
			t.Errorf("unexpected ip matcher %q (geoip:рф must be dropped)", ip)
		}
	}
	if len(ips) != 4 {
		t.Errorf("want 4 ip matchers (geoip:рф dropped), got %v", ips)
	}
}

func TestDirectOutbound_ResolvesThroughSockopt(t *testing.T) {
	cfg := &xrayConf.Config{}
	ensureDirectOutbound(RoutingProfile{DirectInterface: "Ethernet"}, cfg)
	ob := cfg.OutboundConfigs[0]
	if ob.Settings != nil {
		t.Fatalf("freedom settings = %s, want none: its domainStrategy is deprecated", *ob.Settings)
	}
	socket := ob.StreamSetting.SocketSettings
	if socket.DomainStrategy != "UseIP" || socket.Interface != "Ethernet" {
		t.Fatalf("sockopt = %+v", socket)
	}
}
