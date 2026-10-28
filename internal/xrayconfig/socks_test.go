package xrayconfig

import (
	"encoding/json"
	"net"
	"slices"
	"testing"

	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

func TestApplyProxyInbound_Auth(t *testing.T) {
	openCfg := &xrayConf.Config{OutboundConfigs: []xrayConf.OutboundDetourConfig{{Protocol: "freedom", Tag: "proxy"}}}
	if _, err := ApplyProxyInbound(openCfg, 10810, "", ""); err != nil {
		t.Fatalf("ApplyProxyInbound(open): %v", err)
	}
	if got := inboundAuth(t, openCfg); got != "noauth" {
		t.Fatalf("no creds -> auth %q, want noauth", got)
	}
	if _, err := openCfg.Build(); err != nil {
		t.Fatalf("xray rejected open proxy inbound: %v", err)
	}

	authCfg := &xrayConf.Config{OutboundConfigs: []xrayConf.OutboundDetourConfig{{Protocol: "freedom", Tag: "proxy"}}}
	if _, err := ApplyProxyInbound(authCfg, 10811, "alice", `p"ass`); err != nil {
		t.Fatalf("ApplyProxyInbound(auth): %v", err)
	}
	var s struct {
		Auth  string `json:"auth"`
		UDP   bool   `json:"udp"`
		Users []struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		} `json:"users"`
	}
	idx := findInboundIdx(authCfg.InboundConfigs, AppTrafficTag)
	if err := json.Unmarshal(*authCfg.InboundConfigs[idx].Settings, &s); err != nil {
		t.Fatalf("settings unmarshal: %v", err)
	}
	if s.Auth != "password" || len(s.Users) != 1 || s.Users[0].User != "alice" || s.Users[0].Pass != `p"ass` {
		t.Fatalf("auth settings = %+v, want password alice/p\"ass (quote preserved)", s)
	}
	if s.UDP {
		t.Fatal("an inbound with credentials must not carry UDP, which they cannot cover")
	}
	if _, err := authCfg.Build(); err != nil {
		t.Fatalf("xray rejected authed proxy inbound: %v", err)
	}
}

func inboundAuth(t *testing.T, cfg *xrayConf.Config) string {
	t.Helper()
	idx := findInboundIdx(cfg.InboundConfigs, AppTrafficTag)
	if idx < 0 {
		t.Fatal("tun2socks inbound not found")
	}
	var s struct {
		Auth string `json:"auth"`
	}
	if err := json.Unmarshal(*cfg.InboundConfigs[idx].Settings, &s); err != nil {
		t.Fatalf("settings unmarshal: %v", err)
	}
	return s.Auth
}

func TestApplySniffing(t *testing.T) {
	cfg := &xrayConf.Config{
		OutboundConfigs: []xrayConf.OutboundDetourConfig{{Protocol: "freedom", Tag: "proxy"}},
	}
	if _, err := ApplyProxyInbound(cfg, 10808, "", ""); err != nil {
		t.Fatalf("ApplyProxyInbound: %v", err)
	}

	ApplySniffing(cfg, true, false)
	for _, in := range cfg.InboundConfigs {
		if got := len(in.SniffingConfig.DestOverride); got != 4 {
			t.Fatalf("sniffing on: inbound %q destOverride = %v, want full set", in.Tag, in.SniffingConfig.DestOverride)
		}
	}

	ApplySniffing(cfg, false, false)
	for _, in := range cfg.InboundConfigs {
		sc := in.SniffingConfig
		if sc == nil || !sc.Enabled || !sc.RouteOnly {
			t.Fatalf("sniffing off: inbound %q must keep Enabled+RouteOnly: %+v", in.Tag, sc)
		}
		if len(sc.DestOverride) != 1 || sc.DestOverride[0] != "fakedns" {
			t.Fatalf("sniffing off: inbound %q destOverride = %v, want [fakedns]", in.Tag, sc.DestOverride)
		}
	}

	// The trimmed sniffer set must be valid to xray in fake-ip mode.
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, RoutingProfile{}, "warning")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	full := res.Config
	ApplyDNS(full, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}, RoutingProfile{})
	if _, err := ApplyProxyInbound(full, 10808, "", ""); err != nil {
		t.Fatalf("ApplyProxyInbound: %v", err)
	}
	ApplySniffing(full, false, false)
	if _, err := full.Build(); err != nil {
		t.Fatalf("cfg.Build() with fakedns-only sniffing failed: %v", err)
	}
}

// An in-process dial sniffs what an inbound would: the TUN path has no
// inbound to carry the set.
func TestAppSniffing_MatchesTheInboundSet(t *testing.T) {
	for _, content := range []bool{true, false} {
		cfg := &xrayConf.Config{}
		if _, err := ApplyProxyInbound(cfg, 10808, "", ""); err != nil {
			t.Fatalf("ApplyProxyInbound: %v", err)
		}
		ApplySniffing(cfg, content, false)
		sc := cfg.InboundConfigs[0].SniffingConfig
		got, err := AppSniffing(content, false)
		if err != nil {
			t.Fatalf("AppSniffing: %v", err)
		}
		if !got.Enabled || got.RouteOnly != sc.RouteOnly || !slices.Equal(got.OverrideDestinationForProtocol, []string(sc.DestOverride)) {
			t.Fatalf("content sniffing %v: AppSniffing = %+v, inbound = %+v", content, got, sc)
		}
	}
}

// The TUN path dials in process, so a TUN-path config must leave xray with
// no listener of its own.
func TestBuildConfig_OpensNoInbound(t *testing.T) {
	res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, RoutingProfile{
		Mode:  ModeDirectAll,
		Tiers: []routing.Tier{{Proxy: []string{"process:app.exe"}}},
	}, "warning")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	ApplyDNS(res.Config, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}, RoutingProfile{})
	if n := len(res.Config.InboundConfigs); n != 0 {
		t.Fatalf("TUN-path config has %d inbounds, want none", n)
	}
	if _, err := res.Config.Build(); err != nil {
		t.Fatalf("cfg.Build(): %v", err)
	}
}

// Content sniffing skips every local network except the fake-IP pools, whose
// restoration is a sniffer too.
func TestAppSniffing_ExcludesLocalNetworksButNotTheFakePools(t *testing.T) {
	request, err := AppSniffing(true, true)
	if err != nil {
		t.Fatalf("AppSniffing: %v", err)
	}
	for ip, excluded := range map[string]bool{
		"192.168.1.1":  true,
		"10.0.0.1":     true,
		"127.0.0.1":    true,
		"169.254.1.1":  true,
		"fd00::1":      true,
		"fe80::1":      true,
		"fc00:4000::1": true,
		"fc01::1":      true,
		"fc00::1":      false,
		"fc00:3fff::1": false,
		"198.19.0.5":   false,
		"8.8.8.8":      false,
		"2001:db8::1":  false,
	} {
		if got := request.ExcludeForIP.Match(net.ParseIP(ip)); got != excluded {
			t.Errorf("%s excluded = %v, want %v", ip, got, excluded)
		}
	}
	if open, err := AppSniffing(true, false); err != nil || open.ExcludeForIP != nil {
		t.Fatalf("local networks must be sniffed when the option is off: %v %v", open.ExcludeForIP, err)
	}

	cfg := &xrayConf.Config{}
	if _, err := ApplyProxyInbound(cfg, 10808, "", ""); err != nil {
		t.Fatalf("ApplyProxyInbound: %v", err)
	}
	ApplySniffing(cfg, true, true)
	if len(cfg.InboundConfigs[0].SniffingConfig.IPsExcluded) == 0 {
		t.Fatal("the proxy inbound must exclude the local networks too")
	}
	if _, err := cfg.Build(); err != nil {
		t.Fatalf("cfg.Build(): %v", err)
	}
}
