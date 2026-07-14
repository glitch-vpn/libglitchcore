package xrayconfig

import (
	"encoding/json"
	"testing"

	xrayConf "github.com/xtls/xray-core/infra/conf"
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
	if len(rules) != 1 {
		t.Fatalf("default profile: want 1 rule, got %d: %+v", len(rules), rules)
	}
	r := rules[0]
	if r.OutboundTag != "proxy" || len(r.InboundTag) != 1 || r.InboundTag[0] != "tun2socks" {
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
		Block:         []string{"ads.example"},
		Direct:        []string{"domain:bank.example"},
		LocalNetworks: true,
	}
	cfg, rules := applyTo(t, p, "proxy", false)

	// Bare "ads.example" -> domain suffix; "domain:bank.example" -> same syntax.
	if rules[0].OutboundTag != blockTag || rules[0].Domain[0] != "domain:ads.example" {
		t.Errorf("first rule must be block: %+v", rules[0])
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
		Proxy: []string{"domain:youtube.com"},
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
		Mode:   ModeProxyAll,
		Direct: []string{"process:Discord.exe"},
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
		Proxy: []string{"process:torrent.exe"},
	}
	_, rules := applyTo(t, p, "proxy", false)

	var forceRule, catchAll *ruleView
	for i := range rules {
		for _, tag := range rules[i].InboundTag {
			if tag == "forceproxy" {
				forceRule = &rules[i]
			}
			if tag == "tun2socks" {
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
	_, plain := applyTo(t, RoutingProfile{Direct: []string{"process:App.exe"}}, "proxy", false)
	for _, r := range plain {
		for _, tag := range r.InboundTag {
			if tag == "forceproxy" {
				t.Fatalf("forceproxy rule must not appear without a process->proxy rule")
			}
		}
	}
}

func TestApply_DisableIPv6AndUDP(t *testing.T) {
	p := RoutingProfile{
		Block:       []string{"ads.example"},
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
	if len(rules[2].Domain) != 1 || rules[2].Domain[0] != "domain:ads.example" {
		t.Fatalf("explicit block matchers must follow the kill-switches: %+v", rules[2])
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

func TestMatcherRules_Classification(t *testing.T) {
	p := RoutingProfile{
		Mode: ModeProxyAll,
		Direct: []string{
			"geosite:category-ru", "geoip:ru", "domain:рф", "full:exact.example",
			"keyword:ads", "regexp:.*\\.cn$", "48.123.243.123", "10.0.0.0/8",
			"geoip:рф", // invalid geo code -> dropped
		},
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
	wantIP := map[string]bool{"geoip:ru": true, "48.123.243.123": true, "10.0.0.0/8": true}
	for _, ip := range ips {
		if !wantIP[ip] {
			t.Errorf("unexpected ip matcher %q (geoip:рф must be dropped)", ip)
		}
	}
	if len(ips) != 3 {
		t.Errorf("want 3 ip matchers (geoip:рф dropped), got %v", ips)
	}
}
