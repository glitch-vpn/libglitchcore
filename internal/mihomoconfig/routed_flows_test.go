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

// mihomo caches the "cn" list it verifies a geo database by, for the process:
// a test that loads valid files makes the unusable-file check in
// TestBuildConfig_GeoAssetsAreCallerSupplied pass vacuously, so this file sorts
// after mihomoconfig_test.go and runs behind it.
// useGeoFiles points mihomo's home at made-up geo databases: glitch-test is
// 198.51.100.0/24 and glitch.test, cn is 203.0.113.0/24.
func useGeoFiles(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	site, err := proto.Marshal(&xgeodata.GeoSiteList{Entry: []*xgeodata.GeoSite{
		{Code: "GLITCH-TEST", Domain: []*xgeodata.Domain{{Type: xgeodata.Domain_Domain, Value: "glitch.test"}}},
		{Code: "CN", Domain: []*xgeodata.Domain{{Type: xgeodata.Domain_Domain, Value: "cn.glitch.test"}}},
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
	t.Cleanup(func() { C.SetHomeDir(prev) })
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
		prof := routing.Profile{Mode: routing.ModeDirectAll, Tiers: tiers}
		if !withBlock {
			prof.Tiers = tiers[:1]
			prof.Tiers[0].Proxy = []string{"process:app.exe"}
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
