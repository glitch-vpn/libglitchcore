package mihomoconfig

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	_ "unsafe"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/process"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
	xgeodata "github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

//go:linkname resolveMetadata github.com/metacubex/mihomo/tunnel.resolveMetadata
func resolveMetadata(metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error)

// useGeoFiles points mihomo's home at made-up geo databases: glitch-test is
// 198.51.100.0/24 and glitch.test, cn is 203.0.113.0/24, ads-test is ads.test.
func useGeoFiles(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	site, err := proto.Marshal(&xgeodata.GeoSiteList{Entry: []*xgeodata.GeoSite{
		{Code: "GLITCH-TEST", Domain: []*xgeodata.Domain{{Type: xgeodata.Domain_Domain, Value: "glitch.test"}}},
		{Code: "CN", Domain: []*xgeodata.Domain{{Type: xgeodata.Domain_Domain, Value: "cn.glitch.test"}}},
		{Code: "ADS-TEST", Domain: []*xgeodata.Domain{{Type: xgeodata.Domain_Domain, Value: "ads.test"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ip, err := proto.Marshal(&xgeodata.GeoIPList{Entry: []*xgeodata.GeoIP{
		{Code: "GLITCH-TEST", Cidr: []*xgeodata.CIDR{{Ip: net.ParseIP("198.51.100.0").To4(), Prefix: 24}}},
		{Code: "CN", Cidr: []*xgeodata.CIDR{{Ip: net.ParseIP("203.0.113.0").To4(), Prefix: 24}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"geosite.dat": site, "geoip.dat": ip} {
		if err := os.WriteFile(filepath.Join(home, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prev := C.Path.HomeDir()
	C.SetHomeDir(home)
	// mihomo caches a geo matcher by list name, whichever file it came from.
	geodata.ClearGeoSiteCache()
	geodata.ClearGeoIPCache()
	t.Cleanup(func() {
		C.SetHomeDir(prev)
		geodata.ClearGeoSiteCache()
		geodata.ClearGeoIPCache()
	})
}

type routedFlow struct {
	name    string
	inbound string
	network C.NetWork
	host    string
	ip      string
	process string
	want    string
}

// routeFlows runs each flow through mihomo's own matcher on the built config.
func routeFlows(t *testing.T, cfg *config.Config, target string, flows []routedFlow) {
	t.Helper()
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers)
	tunnel.UpdateRules(cfg.Rules, cfg.SubRules, cfg.RuleProviders)
	tunnel.SetMode(tunnel.Rule)
	prevMode := geodata.GeodataMode()
	geodata.SetGeodataMode(true)
	t.Cleanup(func() { geodata.SetGeodataMode(prevMode) })
	tunnel.SetFindProcessMode(process.FindProcessOff)
	for _, f := range flows {
		md := &C.Metadata{NetWork: f.network, Type: C.TUN, InName: f.inbound, Host: f.host, DstPort: 443, Process: f.process}
		if f.ip != "" {
			md.DstIP = netip.MustParseAddr(f.ip)
		}
		proxy, rule, err := resolveMetadata(md)
		if err != nil {
			t.Errorf("%s: %v", f.name, err)
			continue
		}
		want := f.want
		if want == "target" {
			want = target
		}
		if proxy.Name() != want {
			via := "no rule"
			if rule != nil {
				via = rule.RuleType().String() + "," + rule.Payload()
			}
			t.Errorf("%s -> %s (%s), want %s", f.name, proxy.Name(), via, want)
		}
	}
}

const forceFlowLink = "vless://49c8fb89-9418-4ff4-8505-7a2772fc4b71@1.2.3.4:443?type=tcp&security=reality&encryption=none&sni=www.bing.com&fp=chrome&pbk=gdtgDEXry6dpwsJIyDnd6qVxUDMk9jRAthZnqHyDIUI&sid=455f9e232c6fb72d&flow=xtls-rprx-vision#a"

func forceFlowProfile(localNetworks bool) routing.Profile {
	return routing.Profile{
		Mode: routing.ModeDirectAll,
		Tiers: []routing.Tier{
			{Direct: []string{"domain:example.com", "geoip:glitch-test", "203.0.113.0/24"}},
			{Block: []string{
				"regexp:^(ads|track)[.]example[.]com$",
				"keyword:kw(1)",
				"full:exact.example.com",
				"geosite:glitch-test",
				"geoip:cn",
				"192.0.2.0/24",
				"192.168.5.0/24",
			}, Proxy: []string{"process:app.exe"}},
			{Block: []string{"domain:later.example.com"}},
		},
		LocalNetworks: localNetworks,
		DisableIPv6:   true,
		DisableUDP:    true,
	}
}

// A per-app VPN flow meets the kill-switches, then every tier's block, then
// goes to the proxy; every other flow sees the tiers as written.
func TestBuildConfig_ForceProxyRoutesByBlockThenProxy(t *testing.T) {
	useGeoFiles(t)
	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}
	cfg, err := BuildConfig([]string{forceFlowLink}, Inbound{Bridge: true, ForceProxy: true, DNS: dns}, Options{}, forceFlowProfile(true))
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	f, app := ForceProxyInName, ""
	tcp, udp := C.TCP, C.UDP
	routeFlows(t, cfg, Target([]string{forceFlowLink}), []routedFlow{
		{"force regex block", f, tcp, "track.example.com", "", "", "REJECT"},
		{"force keyword block", f, tcp, "xkw(1)y.org", "", "", "REJECT"},
		{"force full block", f, tcp, "exact.example.com", "", "", "REJECT"},
		{"force geosite block", f, tcp, "sub.glitch.test", "", "", "REJECT"},
		{"force geoip block", f, tcp, "", "203.0.113.9", "", "REJECT"},
		{"force cidr block", f, tcp, "", "192.0.2.4", "", "REJECT"},
		{"force later tier block", f, tcp, "later.example.com", "", "", "REJECT"},
		{"force direct domain goes to proxy", f, tcp, "www.example.com", "", "", "target"},
		{"force direct geoip goes to proxy", f, tcp, "", "198.51.100.7", "", "target"},
		{"force unlisted", f, tcp, "other.org", "", "", "target"},
		{"force local network goes direct", f, tcp, "", "192.168.1.1", "", "DIRECT"},
		{"force blocked local network", f, tcp, "", "192.168.5.9", "", "REJECT"},
		{"force udp kill-switch", f, udp, "", "8.8.8.8", "", "REJECT"},
		{"force v6 kill-switch", f, tcp, "", "2001:db8::1", "", "REJECT"},
		{"normal block", app, tcp, "", "192.0.2.4", "", "REJECT"},
		{"normal keyword block", app, tcp, "xkw(1)y.org", "", "", "REJECT"},
		{"normal direct domain", app, tcp, "www.example.com", "", "", "DIRECT"},
		{"normal direct wins over later geoip block", app, tcp, "", "203.0.113.9", "", "DIRECT"},
		{"normal unlisted", app, tcp, "other.org", "", "", "DIRECT"},
		{"normal process proxy", app, tcp, "other.org", "", "app.exe", "target"},
	})
}

// Without the local-networks option a per-app VPN flow to a LAN address goes to
// the proxy; a blocked LAN range stays blocked.
func TestBuildConfig_ForceProxyLocalNetworksOff(t *testing.T) {
	useGeoFiles(t)
	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}
	cfg, err := BuildConfig([]string{forceFlowLink}, Inbound{Bridge: true, ForceProxy: true, DNS: dns}, Options{}, forceFlowProfile(false))
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	f := ForceProxyInName
	routeFlows(t, cfg, Target([]string{forceFlowLink}), []routedFlow{
		{"force local network goes to proxy", f, C.TCP, "", "192.168.1.1", "", "target"},
		{"force blocked local network", f, C.TCP, "", "192.168.5.9", "", "REJECT"},
		{"normal local network", "", C.TCP, "", "192.168.1.1", "", "DIRECT"},
	})
}

// mihomo skips a matched rule whose proxy lacks UDP and tries the next one, so
// a per-app UDP flow must not fall through the sub-rule to the tiers.
func TestBuildRules_ForceProxyUDPDoesNotReachTheTiers(t *testing.T) {
	tiers := []routing.Tier{
		{Direct: []string{"domain:example.com"}},
		{Block: []string{"domain:ads.example"}, Proxy: []string{"process:app.exe"}},
	}
	for _, withBlock := range []bool{true, false} {
		prof := routing.Profile{Mode: routing.ModeDirectAll, Tiers: append([]routing.Tier(nil), tiers...)}
		if !withBlock {
			prof.Tiers = []routing.Tier{{Direct: tiers[0].Direct, Proxy: []string{"process:app.exe"}}}
		}
		raw := config.DefaultRawConfig()
		raw.GeodataMode = true
		raw.Proxy = []map[string]any{{"name": "p", "type": "socks5", "server": "1.2.3.4", "port": 1080, "udp": false}}
		raw.Rule = buildRules(prof, "p", true)
		if withBlock {
			raw.SubRules = map[string][]string{forceFlowsSubRule: forceFlowRules(prof, "p")}
		}
		cfg, err := config.ParseRawConfig(raw)
		if err != nil {
			t.Fatal(err)
		}
		routeFlows(t, cfg, "p", []routedFlow{
			{"force udp to a direct-tier domain", ForceProxyInName, C.UDP, "www.example.com", "", "", "REJECT"},
			{"force tcp to a direct-tier domain", ForceProxyInName, C.TCP, "www.example.com", "", "", "target"},
			{"normal udp to a direct-tier domain", "", C.UDP, "www.example.com", "", "", "DIRECT"},
		})
	}
}

// A flow carrying a name and a local address must not go direct: DIRECT dials
// the name, which can resolve to another address.
func TestBuildConfig_NamedFlowNeverGoesDirectOnLocalNetworks(t *testing.T) {
	prof := routing.Profile{
		Mode:          routing.ModeProxyAll,
		Tiers:         []routing.Tier{{Proxy: []string{"process:app.exe"}}},
		LocalNetworks: true,
	}
	dns := dnsconfig.Config{Mode: dnsconfig.ModeNormal, Servers: []string{"1.1.1.1"}}
	cfg, err := BuildConfig([]string{forceFlowLink}, Inbound{Bridge: true, ForceProxy: true, DNS: dns}, Options{}, prof)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	f := ForceProxyInName
	routeFlows(t, cfg, Target([]string{forceFlowLink}), []routedFlow{
		{"force named flow with a local address", f, C.TCP, "mixed.test", "10.255.255.1", "", "target"},
		{"normal named flow with a local address", "", C.TCP, "mixed.test", "10.255.255.1", "", "target"},
		{"force local address goes direct", f, C.TCP, "", "10.255.255.1", "", "DIRECT"},
		{"normal local address goes direct", "", C.TCP, "", "10.255.255.1", "", "DIRECT"},
	})
}

// The built config lists the local networks in the sniffer's skip-dst-address
// exactly when local networks go direct; it checks the config field only, not
// what the sniffer does with a flow.
func TestBuildConfig_SnifferSkipDstAddressFollowsLocalNetworks(t *testing.T) {
	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}
	for _, on := range []bool{true, false} {
		prof := routing.Profile{LocalNetworks: on}
		cfg, err := BuildConfig([]string{forceFlowLink}, Inbound{Bridge: true, ForceProxy: true, DNS: dns}, Options{}, prof)
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
		}
		if got := len(cfg.Sniffer.SkipDstAddress) > 0; got != on {
			t.Fatalf("local networks %v: sniffer skip-dst-address = %v", on, cfg.Sniffer.SkipDstAddress)
		}
	}
}

// routeTierFlows routes each flow through mihomo's matcher over a profile
// holding only tier, in both modes. A flow with a host and an IP is one the
// sniffer named; "catch-all" is where the mode sends an unlisted flow.
func routeTierFlows(t *testing.T, tier routing.Tier, flows []routedFlow) {
	t.Helper()
	for _, mode := range []string{routing.ModeProxyAll, routing.ModeDirectAll} {
		t.Run(mode, func(t *testing.T) {
			useGeoFiles(t)
			dns := dnsconfig.Config{Mode: dnsconfig.ModeNormal, Servers: []string{"1.1.1.1"}}
			prof := routing.Profile{Mode: mode, Tiers: []routing.Tier{tier}}
			cfg, err := BuildConfig([]string{forceFlowLink}, Inbound{Bridge: true, ForceProxy: true, DNS: dns}, Options{}, prof)
			if err != nil {
				t.Fatalf("BuildConfig: %v", err)
			}
			catchAll := "target"
			if mode == routing.ModeDirectAll {
				catchAll = "DIRECT"
			}
			resolved := make([]routedFlow, len(flows))
			for i, f := range flows {
				if f.want == "catch-all" {
					f.want = catchAll
				}
				resolved[i] = f
			}
			routeFlows(t, cfg, Target([]string{forceFlowLink}), resolved)
		})
	}
}

// A site named in a tier is an exception to the tier's geoip entry with
// another outcome, by name and by sniffed name.
func TestBuildConfig_NamedSiteIsAnExceptionToItsGeoIP(t *testing.T) {
	f, app, tcp := ForceProxyInName, "", C.TCP
	routeTierFlows(t, routing.Tier{
		Direct: []string{"geoip:glitch-test"},
		Proxy:  []string{"domain:vk.test", "process:app.exe"},
	}, []routedFlow{
		{"named site", app, tcp, "vk.test", "", "", "target"},
		{"named site sniffed on its address", app, tcp, "vk.test", "198.51.100.10", "", "target"},
		{"another address in the geoip", app, tcp, "", "198.51.100.11", "", "DIRECT"},
		{"another name sniffed in the geoip", app, tcp, "news.test", "198.51.100.11", "", "DIRECT"},
		{"another name in the geoip", app, tcp, "news.test", "", "", "catch-all"},
		{"per-app named site sniffed", f, tcp, "vk.test", "198.51.100.10", "", "target"},
		{"per-app address in the geoip", f, tcp, "", "198.51.100.11", "", "target"},
	})
}

// full: comes before domain:, and a longer domain: before a shorter one.
func TestBuildConfig_FullNameIsAnExceptionToItsDomain(t *testing.T) {
	app, tcp := "", C.TCP
	routeTierFlows(t, routing.Tier{
		Direct: []string{"domain:x.test"},
		Proxy:  []string{"full:api.x.test", "domain:shop.x.test", "process:app.exe"},
	}, []routedFlow{
		{"full name", app, tcp, "api.x.test", "", "", "target"},
		{"full name sniffed", app, tcp, "api.x.test", "192.0.2.50", "", "target"},
		{"name under the full name", app, tcp, "v1.api.x.test", "", "", "DIRECT"},
		{"longer domain", app, tcp, "cart.shop.x.test", "", "", "target"},
		{"the domain", app, tcp, "www.x.test", "", "", "DIRECT"},
	})
}

// A narrower address entry is an exception to a wider one and to a geoip
// entry.
func TestBuildConfig_CIDRIsAnExceptionToItsGeoIP(t *testing.T) {
	f, app, tcp := ForceProxyInName, "", C.TCP
	routeTierFlows(t, routing.Tier{
		Block:  []string{"198.51.100.200"},
		Direct: []string{"geoip:glitch-test"},
		Proxy:  []string{"198.51.100.128/25", "process:app.exe"},
	}, []routedFlow{
		{"address in the proxy CIDR", app, tcp, "", "198.51.100.150", "", "target"},
		{"address in the blocked IP", app, tcp, "", "198.51.100.200", "", "REJECT"},
		{"address only in the geoip", app, tcp, "", "198.51.100.7", "", "DIRECT"},
		{"sniffed name in the proxy CIDR", app, tcp, "inner.test", "198.51.100.150", "", "target"},
		{"per-app address in the blocked IP", f, tcp, "", "198.51.100.200", "", "REJECT"},
		{"per-app address in the proxy CIDR", f, tcp, "", "198.51.100.150", "", "target"},
	})
}

// A domain: block inside a geosite direct blocks, and a domain: direct inside
// a geosite block goes direct. A per-app VPN flow meets every block, so the
// direct exception does not reach it.
func TestBuildConfig_NamedSiteIsAnExceptionToItsGeoSite(t *testing.T) {
	f, app, tcp := ForceProxyInName, "", C.TCP
	routeTierFlows(t, routing.Tier{
		Block:  []string{"geosite:ads-test", "domain:ads.glitch.test"},
		Direct: []string{"geosite:glitch-test", "domain:good.ads.test"},
		Proxy:  []string{"process:app.exe"},
	}, []routedFlow{
		{"blocked site in a direct geosite", app, tcp, "ads.glitch.test", "", "", "REJECT"},
		{"another site in the direct geosite", app, tcp, "www.glitch.test", "", "", "DIRECT"},
		{"direct site in a blocked geosite", app, tcp, "good.ads.test", "", "", "DIRECT"},
		{"direct site sniffed", app, tcp, "good.ads.test", "192.0.2.50", "", "DIRECT"},
		{"another site in the blocked geosite", app, tcp, "x.ads.test", "", "", "REJECT"},
		{"per-app blocked site", f, tcp, "ads.glitch.test", "", "", "REJECT"},
		{"per-app direct site in a blocked geosite", f, tcp, "good.ads.test", "", "", "REJECT"},
		{"per-app site in the direct geosite", f, tcp, "www.glitch.test", "", "", "target"},
	})
}

// Entries of equal specificity keep block, then direct, then proxy, ahead of
// a broader block.
func TestBuildConfig_EqualSpecificityKeepsBlockDirectProxy(t *testing.T) {
	app, tcp := "", C.TCP
	routeTierFlows(t, routing.Tier{
		Block:  []string{"geosite:ads-test", "domain:same.glitch.test"},
		Direct: []string{"domain:ads.test", "domain:same.glitch.test", "198.51.100.0/25", "geoip:cn"},
		Proxy:  []string{"domain:ads.test", "domain:same.glitch.test", "198.51.100.0/25", "geoip:cn", "process:app.exe"},
	}, []routedFlow{
		{"same domain blocked", app, tcp, "same.glitch.test", "", "", "REJECT"},
		{"same domain direct ahead of a broader block", app, tcp, "www.ads.test", "", "", "DIRECT"},
		{"same CIDR", app, tcp, "", "198.51.100.7", "", "DIRECT"},
		{"same geoip", app, tcp, "", "203.0.113.7", "", "DIRECT"},
	})
}

// A category does not outrank an address block: geosite: and geoip: share a
// rank, where block wins, and a single address ranks above a keyword.
func TestBuildConfig_CategoryOrKeywordDoesNotBeatAnAddressBlock(t *testing.T) {
	f, app, tcp := ForceProxyInName, "", C.TCP
	routeTierFlows(t, routing.Tier{
		Block:  []string{"geoip:cn", "198.51.100.77"},
		Direct: []string{"keyword:cdn"},
		Proxy:  []string{"geosite:glitch-test", "process:app.exe"},
	}, []routedFlow{
		{"geosite name sniffed on a blocked geoip address", app, tcp, "www.glitch.test", "203.0.113.9", "", "REJECT"},
		{"geosite name", app, tcp, "www.glitch.test", "", "", "target"},
		{"keyword name sniffed on a blocked address", app, tcp, "cdn.example.test", "198.51.100.77", "", "REJECT"},
		{"keyword name", app, tcp, "cdn.example.test", "", "", "DIRECT"},
		{"keyword name sniffed elsewhere", app, tcp, "cdn.example.test", "192.0.2.50", "", "DIRECT"},
		{"per-app geosite name sniffed on a blocked geoip address", f, tcp, "www.glitch.test", "203.0.113.9", "", "REJECT"},
	})
}

// A block yields only to a more specific entry of its own plane: a name entry
// does not take a flow from an address block, nor an address entry from a
// name block. A regexp with commas and parentheses rides the logic rule
// intact.
func TestBuildConfig_NameDoesNotBeatAnAddressBlock(t *testing.T) {
	f, app, tcp := ForceProxyInName, "", C.TCP
	routeTierFlows(t, routing.Tier{
		Block:  []string{"192.0.2.0/24"},
		Direct: []string{"domain:x.test", "regexp:^(good|fine)x{1,2}[.]test$"},
		Proxy:  []string{"process:app.exe"},
	}, []routedFlow{
		{"named site sniffed on a blocked address", app, tcp, "x.test", "192.0.2.10", "", "REJECT"},
		{"regexp site sniffed on a blocked address", app, tcp, "goodxx.test", "192.0.2.10", "", "REJECT"},
		{"blocked address", app, tcp, "", "192.0.2.10", "", "REJECT"},
		{"named site", app, tcp, "x.test", "", "", "DIRECT"},
		{"regexp site elsewhere", app, tcp, "goodxx.test", "198.51.100.9", "", "DIRECT"},
		{"per-app named site sniffed on a blocked address", f, tcp, "x.test", "192.0.2.10", "", "REJECT"},
	})
}

func TestBuildConfig_AddressDoesNotBeatANameBlock(t *testing.T) {
	f, app, tcp := ForceProxyInName, "", C.TCP
	routeTierFlows(t, routing.Tier{
		Block:  []string{"keyword:ads", "geosite:ads-test"},
		Direct: []string{"192.0.2.128/25"},
		Proxy:  []string{"process:app.exe"},
	}, []routedFlow{
		{"keyword-blocked name sniffed in the direct range", app, tcp, "myads.example", "192.0.2.200", "", "REJECT"},
		{"geosite-blocked name sniffed in the direct range", app, tcp, "www.ads.test", "192.0.2.200", "", "REJECT"},
		{"address in the direct range", app, tcp, "", "192.0.2.200", "", "DIRECT"},
		{"clean name sniffed in the direct range", app, tcp, "clean.test", "192.0.2.200", "", "DIRECT"},
		{"per-app blocked name sniffed in the direct range", f, tcp, "www.ads.test", "192.0.2.200", "", "REJECT"},
	})
}

// With an exception in each plane, a flow takes a direct exception only where
// no block of the other plane holds it.
func TestBuildConfig_ExceptionsInBothPlanes(t *testing.T) {
	app, tcp := "", C.TCP
	routeTierFlows(t, routing.Tier{
		Block:  []string{"geosite:ads-test", "geoip:cn"},
		Direct: []string{"full:good.ads.test", "203.0.113.7"},
		Proxy:  []string{"process:app.exe"},
	}, []routedFlow{
		{"name exception", app, tcp, "good.ads.test", "", "", "DIRECT"},
		{"address exception", app, tcp, "", "203.0.113.7", "", "DIRECT"},
		{"both exceptions", app, tcp, "good.ads.test", "203.0.113.7", "", "DIRECT"},
		{"name exception sniffed on a blocked address", app, tcp, "good.ads.test", "203.0.113.9", "", "REJECT"},
		{"blocked name sniffed on the address exception", app, tcp, "www.ads.test", "203.0.113.7", "", "REJECT"},
		{"clean name sniffed on the address exception", app, tcp, "clean.test", "203.0.113.7", "", "DIRECT"},
	})
}
