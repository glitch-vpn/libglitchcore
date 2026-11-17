package mihomoconfig

import (
	"slices"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

func processFirstProfile() routing.Profile {
	return routing.Profile{
		Mode: routing.ModeProxyAll,
		Tiers: []routing.Tier{
			{Direct: []string{"process:direct.exe", "process:both.exe", "domain:example.com"}},
			{Block: []string{"domain:ads.example.com", "geoip:cn", "192.0.2.0/24", "process:banned.exe"}, Proxy: []string{"process:tunneled.exe"}},
			{Block: []string{"domain:later.example.com"}, Proxy: []string{"process:both.exe"}},
		},
		LocalNetworks: true,
		DisableIPv6:   true,
	}
}

func desktopTun(processFirst bool) Inbound {
	return Inbound{Tun: &TunInbound{
		Device:       "GlitchVPN",
		ProcessFirst: processFirst,
		DNS:          dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}},
	}}
}

// On a TUN where mihomo reads the app behind a flow, an app a rule sends
// direct still meets every tier's block, wherever the tier holds it.
func TestBuildConfig_ProcessDirectAppMeetsEveryBlock(t *testing.T) {
	useGeoFiles(t)
	cfg, err := BuildConfig([]string{forceFlowLink}, desktopTun(true), Options{}, processFirstProfile())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	tcp := C.TCP
	routeFlows(t, cfg, Target([]string{forceFlowLink}), []routedFlow{
		{"direct app, name blocked in tier 2", "", tcp, "ads.example.com", "", "direct.exe", "REJECT"},
		{"direct app, geoip blocked in tier 2", "", tcp, "", "203.0.113.9", "direct.exe", "REJECT"},
		{"direct app, address blocked in tier 2", "", tcp, "", "192.0.2.4", "direct.exe", "REJECT"},
		{"direct app, name blocked in tier 3", "", tcp, "later.example.com", "", "direct.exe", "REJECT"},
		{"direct app, unlisted", "", tcp, "other.org", "", "direct.exe", "DIRECT"},
		{"direct app, local network", "", tcp, "", "192.168.1.1", "direct.exe", "DIRECT"},
		{"other app, address blocked", "", tcp, "", "192.0.2.4", "browser.exe", "REJECT"},
		{"other app, direct tier domain", "", tcp, "www.example.com", "", "browser.exe", "DIRECT"},
		{"other app, unlisted", "", tcp, "other.org", "", "browser.exe", "target"},
	})
}

// Block beats direct beats proxy for a process named in several lists, as the
// bridge ordered it, and a proxied app goes to the proxy in every mode.
func TestBuildConfig_ProcessOutcomesRankBlockDirectProxy(t *testing.T) {
	useGeoFiles(t)
	prof := processFirstProfile()
	prof.Mode = routing.ModeDirectAll
	prof.Tiers[0].Direct = append(prof.Tiers[0].Direct, "process:banned.exe")
	cfg, err := BuildConfig([]string{forceFlowLink}, desktopTun(true), Options{}, prof)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	tcp := C.TCP
	routeFlows(t, cfg, Target([]string{forceFlowLink}), []routedFlow{
		{"blocked beats direct", "", tcp, "other.org", "", "banned.exe", "REJECT"},
		{"direct beats proxy", "", tcp, "other.org", "", "both.exe", "DIRECT"},
		{"proxied app in direct-all mode", "", tcp, "other.org", "", "tunneled.exe", "target"},
		{"proxied app meets a block", "", tcp, "ads.example.com", "", "tunneled.exe", "REJECT"},
		{"proxied app, local network", "", tcp, "", "192.168.1.1", "tunneled.exe", "DIRECT"},
		{"proxied app, v6 kill-switch", "", tcp, "", "2001:db8::1", "tunneled.exe", "REJECT"},
		{"unlisted app in direct-all mode", "", tcp, "other.org", "", "browser.exe", "DIRECT"},
	})
}

// Without the option the process rules keep their tier's place, so a direct
// app's flow goes direct ahead of a block in a later tier: the order the
// option exists to replace.
func TestBuildConfig_ProcessRulesKeepTierOrderWithoutProcessFirst(t *testing.T) {
	useGeoFiles(t)
	cfg, err := BuildConfig([]string{forceFlowLink}, desktopTun(false), Options{}, processFirstProfile())
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	routeFlows(t, cfg, Target([]string{forceFlowLink}), []routedFlow{
		{"direct app, name blocked in a later tier", "", C.TCP, "ads.example.com", "", "direct.exe", "DIRECT"},
	})
}

// mihomo moves on from a matched rule whose proxy lacks UDP, so a proxied
// app's flow is refused where the sub-rule lets it fall through.
func TestProcessFirstRules_ProxiedAppFallsThroughToARefusal(t *testing.T) {
	rules, _ := processFirstRules(processFirstProfile(), "vpn")
	want := "PROCESS-NAME,tunneled.exe,REJECT"
	if !slices.Contains(rules, want) {
		t.Fatalf("rules %v lack %q", rules, want)
	}
}

func TestProcessFirstRules_SortsNamesAndSkipsEmptyOutcomes(t *testing.T) {
	prof := routing.Profile{Tiers: []routing.Tier{{Direct: []string{"process:b.exe", "process:a.exe"}}}}
	rules, subRules := processFirstRules(prof, "vpn")
	want := "OR,((PROCESS-NAME,a.exe),(PROCESS-NAME,b.exe)),DIRECT"
	if got := strings.Join(rules, "\n"); got != want {
		t.Fatalf("rules = %q, want %q", got, want)
	}
	if len(subRules) != 0 {
		t.Fatalf("a profile without blocks has sub-rules %v", subRules)
	}
	if rules, subRules := processFirstRules(routing.Profile{}, "vpn"); len(rules) != 0 || len(subRules) != 0 {
		t.Fatalf("a profile without process rules has rules %v, %v", rules, subRules)
	}
}

// On the desktop adapter sing-tun gives the adapter a DNS address of its own,
// where the :53 hijack answers, and with a strict route blocks DNS on every
// other interface; an fd the platform made is left as it is.
func TestBuildConfig_TunKeepsDNSInsideTheAdapter(t *testing.T) {
	link := "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=none"
	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}
	strict, err := BuildConfig([]string{link}, Inbound{Tun: &TunInbound{Device: "GlitchVPN", StrictRoute: true, DNS: dns}}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatal(err)
	}
	if tun := strict.General.Tun; !tun.StrictRoute || tun.DNSMode != "hijack" || !tun.AutoRoute {
		t.Fatalf("strict route %v, dns mode %q, auto-route %v, want strict, hijack and auto-routed", tun.StrictRoute, tun.DNSMode, tun.AutoRoute)
	}
	open, err := BuildConfig([]string{link}, Inbound{Tun: &TunInbound{Device: "GlitchVPN", DNS: dns}}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatal(err)
	}
	if open.General.Tun.StrictRoute {
		t.Fatal("a strict route nobody asked for")
	}
	fd, err := BuildConfig([]string{link}, Inbound{Tun: &TunInbound{FileDescriptor: 42, StrictRoute: true, DNS: dns}}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatal(err)
	}
	if tun := fd.General.Tun; tun.StrictRoute || tun.DNSMode != "" {
		t.Fatalf("a platform fd has strict route %v and dns mode %q, want neither", tun.StrictRoute, tun.DNSMode)
	}
}

func TestBuildConfig_TunUDPTimeout(t *testing.T) {
	link := "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=none"
	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}
	set, err := BuildConfig([]string{link}, Inbound{Tun: &TunInbound{Device: "GlitchVPN", MTU: 1380, UDPTimeoutSec: 45, DNS: dns}}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatal(err)
	}
	if set.General.Tun.UDPTimeout != 45 || set.General.Tun.MTU != 1380 {
		t.Fatalf("udp timeout %d, mtu %d, want 45 and 1380", set.General.Tun.UDPTimeout, set.General.Tun.MTU)
	}
	unset, err := BuildConfig([]string{link}, Inbound{Tun: &TunInbound{Device: "GlitchVPN", DNS: dns}}, Options{}, routing.Profile{})
	if err != nil {
		t.Fatal(err)
	}
	if unset.General.Tun.UDPTimeout != 0 {
		t.Fatalf("udp timeout %d without one set, want mihomo's own (0)", unset.General.Tun.UDPTimeout)
	}
}

// With local networks direct, the private ranges stay off the adapter's
// routes, as on the other TUN layers; without, and on a TUN the platform
// routes, nothing is excluded.
func TestBuildConfig_TunKeepsLocalNetworksOffItsRoutes(t *testing.T) {
	link := "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=none"
	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}
	excluded := func(tun *TunInbound, localNetworks bool) []string {
		cfg, err := BuildConfig([]string{link}, Inbound{Tun: tun}, Options{}, routing.Profile{LocalNetworks: localNetworks})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, prefix := range cfg.General.Tun.RouteExcludeAddress {
			out = append(out, prefix.String())
		}
		return out
	}
	desktop := &TunInbound{Device: "GlitchVPN", DNS: dns}
	if got := excluded(desktop, true); !slices.Equal(got, []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}) {
		t.Errorf("local networks direct excluded %v, want the three private ranges", got)
	}
	if got := excluded(desktop, false); len(got) != 0 {
		t.Errorf("local networks proxied excluded %v, want none", got)
	}
	if got := excluded(&TunInbound{FileDescriptor: 7, DNS: dns}, true); len(got) != 0 {
		t.Errorf("an fd TUN excluded %v, want none: the platform routes it", got)
	}
}
