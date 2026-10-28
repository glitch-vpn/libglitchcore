package xrayconfig

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"
	xrouting "github.com/xtls/xray-core/features/routing"
	rsession "github.com/xtls/xray-core/features/routing/session"
	_ "github.com/xtls/xray-core/main/distro/all"
	"google.golang.org/protobuf/proto"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// useGeoFiles points xray at made-up geo databases: glitch-test is
// 198.51.100.0/24 and glitch.test, cn is 203.0.113.0/24.
func useGeoFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	site, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{Code: "GLITCH-TEST", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "glitch.test"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ip, err := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "GLITCH-TEST", Cidr: []*geodata.CIDR{{Ip: net.ParseIP("198.51.100.0").To4(), Prefix: 24}}},
		{Code: "CN", Cidr: []*geodata.CIDR{{Ip: net.ParseIP("203.0.113.0").To4(), Prefix: 24}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"geosite.dat": site, "geoip.dat": ip} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("xray.location.asset", dir)
}

func routedFlowProfile(localNetworks bool) routing.Profile {
	return routing.Profile{
		Mode: routing.ModeDirectAll,
		Tiers: []routing.Tier{
			{Direct: []string{"domain:example.com", "geoip:glitch-test", "203.0.113.0/24"}},
			{Block: []string{
				"regexp:^a{2,5}[.]example[.]com$",
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

type routedFlow struct {
	name    string
	inbound string
	network xnet.Network
	address string
	port    uint16
	want    string
}

// routeFlows runs each flow through xray's own router on the built config.
func routeFlows(t *testing.T, prof routing.Profile, flows []routedFlow) {
	t.Helper()
	if err := prof.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := BuildConfig([]string{"vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=tcp&security=none#t"}, BalancerOptions{}, prof, "none")
	if err != nil {
		t.Fatal(err)
	}
	ApplyDNS(res.Config, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}, Hosts: map[string][]string{"mixed.test": {"10.255.255.1", "203.0.113.7"}}}, prof)
	built, err := res.Config.Build()
	if err != nil {
		t.Fatal(err)
	}
	inst, err := xrayCore.New(built)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()
	router := inst.GetFeature(xrouting.RouterType()).(xrouting.Router)
	for _, f := range flows {
		dest := xnet.Destination{Network: f.network, Address: xnet.ParseAddress(f.address), Port: xnet.Port(f.port)}
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: dest}})
		ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: f.inbound})
		route, err := router.PickRoute(rsession.AsRoutingContext(ctx))
		if err != nil {
			t.Errorf("%s: %v", f.name, err)
			continue
		}
		if got := route.GetOutboundTag(); got != f.want {
			t.Errorf("%s -> %s, want %s", f.name, got, f.want)
		}
	}
}

// A per-app VPN flow meets the kill-switches, every tier's block, then the
// local networks, then goes to the proxy; every other flow sees the tiers as
// written.
func TestApply_ForceProxyRoutesByBlockThenProxy(t *testing.T) {
	useGeoFiles(t)
	f, app := ForceProxyTag, AppTrafficTag
	tcp, udp := xnet.Network_TCP, xnet.Network_UDP
	routeFlows(t, routedFlowProfile(true), []routedFlow{
		{"force regex block", f, tcp, "aa.example.com", 443, blockTag},
		{"force keyword block", f, tcp, "xkw(1)y.org", 443, blockTag},
		{"force full block", f, tcp, "exact.example.com", 443, blockTag},
		{"force geosite block", f, tcp, "sub.glitch.test", 443, blockTag},
		{"force geoip block", f, tcp, "203.0.113.9", 443, blockTag},
		{"force cidr block", f, tcp, "192.0.2.4", 443, blockTag},
		{"force later tier block", f, tcp, "later.example.com", 443, blockTag},
		{"force direct domain goes to proxy", f, tcp, "www.example.com", 443, OutboundTag},
		{"force direct geoip goes to proxy", f, tcp, "198.51.100.7", 443, OutboundTag},
		{"force unlisted", f, tcp, "other.org", 443, OutboundTag},
		{"force local network goes direct", f, tcp, "192.168.1.1", 80, directTag},
		{"force blocked local network", f, tcp, "192.168.5.9", 80, blockTag},
		{"force udp kill-switch", f, udp, "8.8.8.8", 443, blockTag},
		{"force v6 kill-switch", f, tcp, "2001:db8::1", 443, blockTag},
		{"normal keyword block", app, tcp, "xkw(1)y.org", 443, blockTag},
		{"normal direct geoip wins over cn block", app, tcp, "203.0.113.9", 443, directTag},
		{"normal cidr block", app, tcp, "192.0.2.4", 443, blockTag},
		{"normal direct domain", app, tcp, "www.example.com", 443, directTag},
		{"normal local network", app, tcp, "192.168.1.1", 80, directTag},
		{"normal unlisted", app, tcp, "other.org", 443, directTag},
		{"exit echo bypasses blocks", ExitEchoTag, tcp, "aa.example.com", 443, OutboundTag},
	})
}

// Without the local-networks option a per-app VPN flow to a LAN address goes
// to the proxy; a blocked LAN range stays blocked.
func TestApply_ForceProxyLocalNetworksOff(t *testing.T) {
	useGeoFiles(t)
	f := ForceProxyTag
	routeFlows(t, routedFlowProfile(false), []routedFlow{
		{"force local network goes to proxy", f, xnet.Network_TCP, "192.168.1.1", 80, OutboundTag},
		{"force blocked local network", f, xnet.Network_TCP, "192.168.5.9", 80, blockTag},
	})
}

// A name answering a local and a public address never goes direct on the
// local-networks rule, whatever the router's domain strategy: the direct
// outbound would dial whichever address it resolves.
func TestApply_NamedFlowNeverGoesDirectOnLocalNetworks(t *testing.T) {
	for _, strategy := range []string{"AsIs", "IPIfNonMatch", "IPOnDemand"} {
		t.Run(strategy, func(t *testing.T) {
			prof := routing.Profile{
				Mode:           routing.ModeProxyAll,
				Tiers:          []routing.Tier{{Proxy: []string{"process:app.exe"}}},
				LocalNetworks:  true,
				DomainStrategy: strategy,
			}
			tcp := xnet.Network_TCP
			routeFlows(t, prof, []routedFlow{
				{"force named flow", ForceProxyTag, tcp, "mixed.test", 443, OutboundTag},
				{"normal named flow", AppTrafficTag, tcp, "mixed.test", 443, OutboundTag},
				{"force local address", ForceProxyTag, tcp, "10.255.255.1", 443, directTag},
				{"normal local address", AppTrafficTag, tcp, "10.255.255.1", 443, directTag},
			})
		})
	}
}
