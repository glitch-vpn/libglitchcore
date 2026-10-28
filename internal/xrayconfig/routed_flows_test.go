package xrayconfig

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
// 198.51.100.0/24 and glitch.test, cn is 203.0.113.0/24, loopback-test is
// 127.0.0.2/32.
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
		{Code: "LOOPBACK-TEST", Cidr: []*geodata.CIDR{{Ip: net.ParseIP("127.0.0.2").To4(), Prefix: 32}}},
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

// startRoutedInstance runs the built config in a started xray instance whose proxy
// outbound dials proxyAddress and whose DNS answers hosts.
func startRoutedInstance(t *testing.T, prof routing.Profile, proxyAddress string, hosts map[string][]string) *xrayCore.Instance {
	t.Helper()
	if err := prof.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := BuildConfig([]string{"vless://11111111-1111-1111-1111-111111111111@" + proxyAddress + "?type=tcp&security=none#t"}, BalancerOptions{}, prof, "none")
	if err != nil {
		t.Fatal(err)
	}
	ApplyDNS(res.Config, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"127.0.0.1:1"}, Hosts: hosts}, prof)
	built, err := res.Config.Build()
	if err != nil {
		t.Fatal(err)
	}
	inst, err := xrayCore.New(built)
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return inst
}

// routeFlows runs each flow through xray's own router on the built config.
func routeFlows(t *testing.T, prof routing.Profile, flows []routedFlow) {
	t.Helper()
	inst := startRoutedInstance(t, prof, "192.0.2.1:443", map[string][]string{
		"mixed.test": {"10.255.255.1", "203.0.113.7"},
		"cn.test":    {"203.0.113.7"},
	})
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
		{"normal direct geoip wins over cn block", app, tcp, "203.0.113.9", 443, tierDirectTag(0)},
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

// Under the strategies that resolve, a tier's geoip block applies to a name
// that resolves into it, on normal and per-app flows alike.
func TestApply_IPBlockAppliesToNames(t *testing.T) {
	for _, strategy := range []string{"IPIfNonMatch", "IPOnDemand"} {
		t.Run(strategy, func(t *testing.T) {
			useGeoFiles(t)
			prof := routing.Profile{
				Mode:           routing.ModeProxyAll,
				Tiers:          []routing.Tier{{Block: []string{"geoip:cn"}, Proxy: []string{"process:app.exe"}}},
				LocalNetworks:  true,
				DomainStrategy: strategy,
			}
			tcp := xnet.Network_TCP
			routeFlows(t, prof, []routedFlow{
				{"normal name in the block", AppTrafficTag, tcp, "cn.test", 443, blockTag},
				{"force name in the block", ForceProxyTag, tcp, "cn.test", 443, blockTag},
				{"normal address outside the block", AppTrafficTag, tcp, "198.51.100.7", 443, OutboundTag},
				{"force address outside the block", ForceProxyTag, tcp, "198.51.100.7", 443, OutboundTag},
			})
		})
	}
}

// dialCounter accepts on a loopback address and counts each connection before
// closing it, so the count is in when the dialer reads the close.
type dialCounter struct {
	hits atomic.Int32
	port int
}

func countDials(t *testing.T, ip string, port int) *dialCounter {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		t.Skipf("listen on %s: %v", ip, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	c := &dialCounter{port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			c.hits.Add(1)
			_ = conn.Close()
		}
	}()
	return c
}

// dialThrough sends one flow into the instance as the inbound would and waits
// for xray to end it. A sniffed flow carries an HTTP request naming sniffedName.
func dialThrough(t *testing.T, inst *xrayCore.Instance, inbound, address string, port int, sniffedName string) {
	t.Helper()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: inbound})
	if sniffedName != "" {
		sniffing, err := AppSniffing(true, false)
		if err != nil {
			t.Fatal(err)
		}
		ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: sniffing})
	}
	conn, err := xrayCore.Dial(ctx, inst, xnet.TCPDestination(xnet.ParseAddress(address), xnet.Port(port)))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + sniffedName + "\r\n\r\n"))
	ended := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		close(ended)
	}()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Errorf("flow to %s as %s did not end", address, inbound)
	}
	_ = conn.Close()
	<-ended
}

// A name the entries cover in part, or a sniffed flow whose own address they
// miss, never reaches the other address directly.
func TestApply_TierDirectByIPDialsOnlyItsAddresses(t *testing.T) {
	const covered, outside = "127.0.0.2", "127.0.0.1"
	// part.test answers both addresses and the direct outbound picks one at
	// random, so enough dials that a leak cannot hide.
	const dials = 16
	type flow struct {
		name, address, sniffedName string
		// normal and perApp: where each dial lands, by strategy - "covered",
		// "proxy", or "none" when it is refused.
		normal, perApp map[string]string
	}
	everywhere := func(where string) map[string]string {
		return map[string]string{"AsIs": where, "IPIfNonMatch": where, "IPOnDemand": where}
	}
	flows := []flow{
		{"fully covered name", "covered.test", "",
			map[string]string{"AsIs": "proxy", "IPIfNonMatch": "covered", "IPOnDemand": "covered"}, everywhere("proxy")},
		{"partly covered name", "part.test", "",
			map[string]string{"AsIs": "proxy", "IPIfNonMatch": "none", "IPOnDemand": "none"}, everywhere("proxy")},
		{"address in the rule", covered, "", everywhere("covered"), everywhere("proxy")},
		{"sniffed name in the rule, address outside", outside, "covered.test",
			map[string]string{"AsIs": "proxy", "IPIfNonMatch": "proxy", "IPOnDemand": "none"}, everywhere("proxy")},
	}
	for _, strategy := range []string{"AsIs", "IPIfNonMatch", "IPOnDemand"} {
		t.Run(strategy, func(t *testing.T) {
			useGeoFiles(t)
			proxyDials := countDials(t, outside, 0)
			// One port on both addresses, so a dial to either is counted.
			outsideDials := countDials(t, outside, 0)
			coveredDials := countDials(t, covered, outsideDials.port)
			prof := routing.Profile{
				Mode: routing.ModeProxyAll,
				Tiers: []routing.Tier{{
					Direct: []string{"geoip:loopback-test", "192.0.2.77/32"},
					Proxy:  []string{"process:app.exe"},
				}},
				DomainStrategy: strategy,
			}
			inst := startRoutedInstance(t, prof, net.JoinHostPort(outside, strconv.Itoa(proxyDials.port)), map[string][]string{
				"covered.test": {covered},
				"part.test":    {covered, outside},
			})
			for _, f := range flows {
				for _, side := range []struct {
					inbound string
					want    map[string]string
				}{{AppTrafficTag, f.normal}, {ForceProxyTag, f.perApp}} {
					before := map[string]int32{"covered": coveredDials.hits.Load(), "proxy": proxyDials.hits.Load(), "outside": outsideDials.hits.Load()}
					var wg sync.WaitGroup
					for range dials {
						wg.Add(1)
						go func() {
							defer wg.Done()
							dialThrough(t, inst, side.inbound, f.address, outsideDials.port, f.sniffedName)
						}()
					}
					wg.Wait()
					got := map[string]int32{
						"covered": coveredDials.hits.Load() - before["covered"],
						"proxy":   proxyDials.hits.Load() - before["proxy"],
						"outside": outsideDials.hits.Load() - before["outside"],
					}
					want := map[string]int32{"covered": 0, "proxy": 0, "outside": 0}
					if where := side.want[strategy]; where != "none" {
						want[where] = dials
					}
					if got["covered"] != want["covered"] || got["proxy"] != want["proxy"] || got["outside"] != want["outside"] {
						t.Errorf("%s as %s: dials landed %v, want %v", f.name, side.inbound, got, want)
					}
				}
			}
		})
	}
}
