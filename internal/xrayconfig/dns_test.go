package xrayconfig

import (
	"encoding/json"
	"strings"
	"testing"

	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
)

const dnsTestLink = "vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=tcp&security=tls&sni=a.example.com"

func TestApplyDNS_TranslatesAndSkipsDoT(t *testing.T) {
	cfg := &xrayConf.Config{}
	ApplyDNS(cfg, dnsconfig.Config{Servers: []string{
		"1.1.1.1",                      // plain UDP -> kept
		"https://dns.google/dns-query", // DoH -> kept
		"quic://dns.adguard.com",       // DoQ -> quic+local://
		"tls://1.1.1.1",                // DoT -> skipped (xray has none)
	}})

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
	ApplyDNS(cfg, dnsconfig.Config{})
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
	})

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

	ApplyDNS(cfg, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}})

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
	ApplyDNS(cfg, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}})
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
	ApplyDNS(cfg, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}, DisableIPv6: true})

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
	ApplyDNS(plain, dnsconfig.Config{Servers: []string{"1.1.1.1"}, DisableIPv6: true})
	if plain.DNSConfig.QueryStrategy != "UseIPv4" {
		t.Fatalf("normal QueryStrategy = %q, want UseIPv4", plain.DNSConfig.QueryStrategy)
	}

	// No servers at all: AAAA suppression must still reach xray's resolver.
	empty := &xrayConf.Config{}
	ApplyDNS(empty, dnsconfig.Config{DisableIPv6: true})
	if empty.DNSConfig == nil || empty.DNSConfig.QueryStrategy != "UseIPv4" {
		t.Fatalf("empty-server DNSConfig = %+v, want UseIPv4", empty.DNSConfig)
	}
}

func TestSniffing_FakednsHarmlessWithoutPool(t *testing.T) {
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, RoutingProfile{}, "warning")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	cfg := res.Config
	ApplyDNS(cfg, dnsconfig.Config{Servers: []string{"1.1.1.1"}}) // normal mode, no pool
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
