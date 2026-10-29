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

	D "github.com/miekg/dns"
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
// 127.0.0.2/32, ads-test is ads.test.
func useGeoFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	site, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{Code: "GLITCH-TEST", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "glitch.test"}}},
		{Code: "ADS-TEST", Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "ads.test"}}},
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

// fakeIPHosts is fake-ip DNS whose own lookups answer from hosts alone.
func fakeIPHosts(hosts map[string][]string) dnsconfig.Config {
	return dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"127.0.0.1:1"}, Hosts: hosts}
}

// startRoutedInstance runs the built config in a started xray instance whose
// proxy outbound dials proxyAddress.
func startRoutedInstance(t *testing.T, prof routing.Profile, proxyAddress string, dns dnsconfig.Config) *xrayCore.Instance {
	t.Helper()
	if err := prof.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := BuildConfig([]string{"vless://11111111-1111-1111-1111-111111111111@" + proxyAddress + "?type=tcp&security=none#t"}, BalancerOptions{}, prof, "none")
	if err != nil {
		t.Fatal(err)
	}
	ApplyDNS(res.Config, dns, prof)
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
	inst := startRoutedInstance(t, prof, "192.0.2.1:443", fakeIPHosts(map[string][]string{
		"mixed.test": {"10.255.255.1", "203.0.113.7"},
		"cn.test":    {"203.0.113.7"},
	}))
	pickRoutes(t, inst, flows)
}

func pickRoutes(t *testing.T, inst *xrayCore.Instance, flows []routedFlow) {
	t.Helper()
	for _, f := range flows {
		dest := xnet.Destination{Network: f.network, Address: xnet.ParseAddress(f.address), Port: xnet.Port(f.port)}
		got, err := pickRoute(inst, f.inbound, dest, "")
		if err != nil {
			t.Errorf("%s: %v", f.name, err)
			continue
		}
		if got != f.want {
			t.Errorf("%s -> %s, want %s", f.name, got, f.want)
		}
	}
}

// pickRoute asks xray's router for a flow's outbound. A sniffed name rides the
// route target, where a routeOnly sniff leaves it.
func pickRoute(inst *xrayCore.Instance, inbound string, dest xnet.Destination, sniffedName string) (string, error) {
	outbound := &session.Outbound{Target: dest}
	if sniffedName != "" {
		outbound.RouteTarget = xnet.Destination{Network: dest.Network, Address: xnet.DomainAddress(sniffedName), Port: dest.Port}
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{outbound})
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: inbound})
	route, err := inst.GetFeature(xrouting.RouterType()).(xrouting.Router).PickRoute(rsession.AsRoutingContext(ctx))
	if err != nil {
		return "", err
	}
	return route.GetOutboundTag(), nil
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
	for _, strategy := range domainStrategies {
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
// that resolves into it. Under IPIfNonMatch a per-app VPN flow's name is never
// resolved, so the block takes it by address only.
func TestApply_IPBlockAppliesToNames(t *testing.T) {
	perAppName := map[string]string{"IPIfNonMatch": OutboundTag, "IPOnDemand": blockTag}
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
				{"force name in the block", ForceProxyTag, tcp, "cn.test", 443, perAppName[strategy]},
				{"force address in the block", ForceProxyTag, tcp, "203.0.113.7", 443, blockTag},
				{"normal address outside the block", AppTrafficTag, tcp, "198.51.100.7", 443, OutboundTag},
				{"force address outside the block", ForceProxyTag, tcp, "198.51.100.7", 443, OutboundTag},
			})
		})
	}
}

// countDNSQueries answers every A query with 198.51.100.9 and counts the queries.
func countDNSQueries(t *testing.T) (address string, queries *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	queries = new(atomic.Int32)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			queries.Add(1)
			var query D.Msg
			if query.Unpack(buf[:n]) != nil {
				continue
			}
			answer := new(D.Msg)
			answer.SetReply(&query)
			if len(query.Question) == 1 && query.Question[0].Qtype == D.TypeA {
				answer.Answer = []D.RR{&D.A{
					Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
					A:   net.ParseIP("198.51.100.9").To4(),
				}}
			}
			if packed, err := answer.Pack(); err == nil {
				_, _ = conn.WriteTo(packed, from)
			}
		}
	}()
	return conn.LocalAddr().String(), queries
}

// Under IPIfNonMatch a per-app VPN flow to a name no rule matches goes to the
// proxy without a lookup, while a normal flow's name is resolved.
func TestApply_PerAppNamesAreNotLookedUp(t *testing.T) {
	resolver, queries := countDNSQueries(t)
	prof := routing.Profile{
		Mode:           routing.ModeProxyAll,
		Tiers:          []routing.Tier{{Block: []string{"192.0.2.0/24"}, Proxy: []string{"process:app.exe"}}},
		LocalNetworks:  true,
		DomainStrategy: "IPIfNonMatch",
	}
	inst := startRoutedInstance(t, prof, "192.0.2.1:443", dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{resolver}})
	tcp := xnet.Network_TCP
	pickRoutes(t, inst, []routedFlow{{"force unmatched name", ForceProxyTag, tcp, "unmatched.test", 443, OutboundTag}})
	if n := queries.Load(); n != 0 {
		t.Fatalf("a per-app VPN flow's name was looked up %d times", n)
	}
	pickRoutes(t, inst, []routedFlow{{"normal unmatched name", AppTrafficTag, tcp, "unmatched.test", 443, OutboundTag}})
	if queries.Load() == 0 {
		t.Fatal("a normal flow's name was not looked up, so the resolver is not reached")
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
	flows := []flow{
		{"fully covered name", "covered.test", "",
			map[string]string{"AsIs": "proxy", "IPIfNonMatch": "covered", "IPOnDemand": "covered"}, everyStrategy("proxy")},
		{"partly covered name", "part.test", "",
			map[string]string{"AsIs": "proxy", "IPIfNonMatch": "none", "IPOnDemand": "none"}, everyStrategy("proxy")},
		{"address in the rule", covered, "", everyStrategy("covered"), everyStrategy("proxy")},
		{"sniffed name in the rule, address outside", outside, "covered.test",
			map[string]string{"AsIs": "proxy", "IPIfNonMatch": "proxy", "IPOnDemand": "none"}, everyStrategy("proxy")},
	}
	for _, strategy := range domainStrategies {
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
			inst := startRoutedInstance(t, prof, net.JoinHostPort(outside, strconv.Itoa(proxyDials.port)), fakeIPHosts(map[string][]string{
				"covered.test": {covered},
				"part.test":    {covered, outside},
			}))
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

// A dual-stack name an IPv4-only direct list covers in part is refused in
// proxy-all mode and goes direct in direct-all, where unlisted names do too.
func TestApply_PartlyCoveredNameByMode(t *testing.T) {
	const dials = 16
	for _, mode := range []string{routing.ModeProxyAll, routing.ModeDirectAll} {
		t.Run(mode, func(t *testing.T) {
			proxyDials := countDials(t, "127.0.0.1", 0)
			v4Dials := countDials(t, "127.0.0.2", 0)
			v6Dials := countDials(t, "::1", v4Dials.port)
			prof := routing.Profile{
				Mode:           mode,
				Tiers:          []routing.Tier{{Direct: []string{"127.0.0.2/32"}}},
				DomainStrategy: "IPOnDemand",
			}
			inst := startRoutedInstance(t, prof, net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyDials.port)),
				fakeIPHosts(map[string][]string{"dual.test": {"127.0.0.2", "::1"}}))
			var wg sync.WaitGroup
			for range dials {
				wg.Add(1)
				go func() {
					defer wg.Done()
					dialThrough(t, inst, AppTrafficTag, "dual.test", v4Dials.port, "")
				}()
			}
			wg.Wait()
			direct, proxied := v4Dials.hits.Load()+v6Dials.hits.Load(), proxyDials.hits.Load()
			wantDirect := int32(0)
			if mode == routing.ModeDirectAll {
				wantDirect = dials
			}
			if direct != wantDirect || proxied != 0 {
				t.Errorf("direct dials %d, proxied %d; want direct %d, proxied 0", direct, proxied, wantDirect)
			}
		})
	}
}

// Where a flow through one tier lands, before the mode and the tier's own
// direct outbound are known.
const (
	toProxy           = OutboundTag
	toDirect          = directTag
	toBlock           = blockTag
	toDirectByAddress = "direct by address" // the tier's own direct outbound in proxy-all
	toCatchAll        = "catch-all"
)

type tierFlow struct {
	name, inbound, address, sniffedName string
	want                                map[string]string // by domain strategy
}

var domainStrategies = []string{"AsIs", "IPIfNonMatch", "IPOnDemand"}

func everyStrategy(where string) map[string]string {
	return map[string]string{"AsIs": where, "IPIfNonMatch": where, "IPOnDemand": where}
}

// routeTierFlows routes each flow through xray's router over a profile holding
// only tier, in both modes and under every domain strategy.
func routeTierFlows(t *testing.T, tier routing.Tier, hosts map[string][]string, flows []tierFlow) {
	t.Helper()
	for _, mode := range []string{routing.ModeProxyAll, routing.ModeDirectAll} {
		for _, strategy := range domainStrategies {
			t.Run(mode+"/"+strategy, func(t *testing.T) {
				useGeoFiles(t)
				prof := routing.Profile{Mode: mode, Tiers: []routing.Tier{tier}, DomainStrategy: strategy}
				inst := startRoutedInstance(t, prof, "192.0.2.1:443", fakeIPHosts(hosts))
				for _, f := range flows {
					want := f.want[strategy]
					switch {
					case want == toDirectByAddress && mode == routing.ModeProxyAll:
						want = tierDirectTag(0)
					case want == toDirectByAddress, want == toCatchAll && mode == routing.ModeDirectAll:
						want = directTag
					case want == toCatchAll:
						want = OutboundTag
					}
					got, err := pickRoute(inst, f.inbound, xnet.TCPDestination(xnet.ParseAddress(f.address), 443), f.sniffedName)
					if err != nil {
						t.Errorf("%s: %v", f.name, err)
						continue
					}
					if got != want {
						t.Errorf("%s -> %s, want %s", f.name, got, want)
					}
				}
			})
		}
	}
}

// A site named in a tier is an exception to the tier's geoip entry with
// another outcome, by name, by sniffed name and once resolved.
func TestApply_NamedSiteIsAnExceptionToItsGeoIP(t *testing.T) {
	app, force := AppTrafficTag, ForceProxyTag
	routeTierFlows(t, routing.Tier{
		Direct: []string{"geoip:glitch-test"},
		Proxy:  []string{"domain:vk.test", "process:app.exe"},
	}, map[string][]string{"vk.test": {"198.51.100.10"}, "news.test": {"198.51.100.11"}}, []tierFlow{
		{"named site", app, "vk.test", "", everyStrategy(toProxy)},
		{"named site sniffed on its address", app, "198.51.100.10", "vk.test", everyStrategy(toProxy)},
		{"another address in the geoip", app, "198.51.100.11", "", everyStrategy(toDirectByAddress)},
		{"another name in the geoip", app, "news.test", "",
			map[string]string{"AsIs": toCatchAll, "IPIfNonMatch": toDirectByAddress, "IPOnDemand": toDirectByAddress}},
		{"per-app named site", force, "vk.test", "", everyStrategy(toProxy)},
		{"per-app address in the geoip", force, "198.51.100.11", "", everyStrategy(toProxy)},
	})
}

// full: comes before domain:, and a longer domain: before a shorter one.
func TestApply_FullNameIsAnExceptionToItsDomain(t *testing.T) {
	app := AppTrafficTag
	routeTierFlows(t, routing.Tier{
		Direct: []string{"domain:x.test"},
		Proxy:  []string{"full:api.x.test", "domain:shop.x.test", "process:app.exe"},
	}, nil, []tierFlow{
		{"full name", app, "api.x.test", "", everyStrategy(toProxy)},
		{"full name sniffed", app, "192.0.2.50", "api.x.test", everyStrategy(toProxy)},
		{"name under the full name", app, "v1.api.x.test", "", everyStrategy(toDirect)},
		{"longer domain", app, "cart.shop.x.test", "", everyStrategy(toProxy)},
		{"the domain", app, "www.x.test", "", everyStrategy(toDirect)},
	})
}

// A narrower address entry is an exception to a wider one and to a geoip
// entry.
func TestApply_CIDRIsAnExceptionToItsGeoIP(t *testing.T) {
	app, force := AppTrafficTag, ForceProxyTag
	routeTierFlows(t, routing.Tier{
		Block:  []string{"198.51.100.200"},
		Direct: []string{"geoip:glitch-test"},
		Proxy:  []string{"198.51.100.128/25", "process:app.exe"},
	}, map[string][]string{"inner.test": {"198.51.100.150"}, "outer.test": {"198.51.100.7"}}, []tierFlow{
		{"address in the proxy CIDR", app, "198.51.100.150", "", everyStrategy(toProxy)},
		{"address in the blocked IP", app, "198.51.100.200", "", everyStrategy(toBlock)},
		{"address only in the geoip", app, "198.51.100.7", "", everyStrategy(toDirectByAddress)},
		{"name in the proxy CIDR", app, "inner.test", "",
			map[string]string{"AsIs": toCatchAll, "IPIfNonMatch": toProxy, "IPOnDemand": toProxy}},
		{"name only in the geoip", app, "outer.test", "",
			map[string]string{"AsIs": toCatchAll, "IPIfNonMatch": toDirectByAddress, "IPOnDemand": toDirectByAddress}},
		{"per-app address in the blocked IP", force, "198.51.100.200", "", everyStrategy(toBlock)},
		{"per-app address in the proxy CIDR", force, "198.51.100.150", "", everyStrategy(toProxy)},
	})
}

// A domain: block inside a geosite direct blocks, and a domain: direct inside
// a geosite block goes direct. A per-app VPN flow meets every block, so the
// direct exception does not reach it.
func TestApply_NamedSiteIsAnExceptionToItsGeoSite(t *testing.T) {
	app, force := AppTrafficTag, ForceProxyTag
	routeTierFlows(t, routing.Tier{
		Block:  []string{"geosite:ads-test", "domain:ads.glitch.test"},
		Direct: []string{"geosite:glitch-test", "domain:good.ads.test"},
		Proxy:  []string{"process:app.exe"},
	}, nil, []tierFlow{
		{"blocked site in a direct geosite", app, "ads.glitch.test", "", everyStrategy(toBlock)},
		{"another site in the direct geosite", app, "www.glitch.test", "", everyStrategy(toDirect)},
		{"direct site in a blocked geosite", app, "good.ads.test", "", everyStrategy(toDirect)},
		{"direct site sniffed", app, "192.0.2.50", "good.ads.test", everyStrategy(toDirect)},
		{"another site in the blocked geosite", app, "x.ads.test", "", everyStrategy(toBlock)},
		{"per-app blocked site", force, "ads.glitch.test", "", everyStrategy(toBlock)},
		{"per-app direct site in a blocked geosite", force, "good.ads.test", "", everyStrategy(toBlock)},
		{"per-app site in the direct geosite", force, "www.glitch.test", "", everyStrategy(toProxy)},
	})
}

// Entries of equal specificity keep block, then direct, then proxy, ahead of
// a broader block.
func TestApply_EqualSpecificityKeepsBlockDirectProxy(t *testing.T) {
	app := AppTrafficTag
	routeTierFlows(t, routing.Tier{
		Block:  []string{"geosite:ads-test", "domain:same.glitch.test"},
		Direct: []string{"domain:ads.test", "domain:same.glitch.test", "198.51.100.0/25", "geoip:cn"},
		Proxy:  []string{"domain:ads.test", "domain:same.glitch.test", "198.51.100.0/25", "geoip:cn", "process:app.exe"},
	}, map[string][]string{"cn.test": {"203.0.113.7"}}, []tierFlow{
		{"same domain blocked", app, "same.glitch.test", "", everyStrategy(toBlock)},
		{"same domain direct ahead of a broader block", app, "www.ads.test", "", everyStrategy(toDirect)},
		{"same CIDR", app, "198.51.100.7", "", everyStrategy(toDirectByAddress)},
		{"same geoip", app, "203.0.113.7", "", everyStrategy(toDirectByAddress)},
		{"name in the same geoip", app, "cn.test", "",
			map[string]string{"AsIs": toCatchAll, "IPIfNonMatch": toDirectByAddress, "IPOnDemand": toDirectByAddress}},
	})
}

// A category does not outrank an address block: geosite: and geoip: share a
// rank, where block wins, and a single address ranks above a keyword. Under
// IPIfNonMatch a name meets every name entry before it is resolved; under
// IPOnDemand xray matches a sniffed flow's IP rules against the addresses its
// name resolves to, not the one the flow carries.
func TestApply_CategoryOrKeywordDoesNotBeatAnAddressBlock(t *testing.T) {
	app, force := AppTrafficTag, ForceProxyTag
	routeTierFlows(t, routing.Tier{
		Block:  []string{"geoip:cn", "198.51.100.77"},
		Direct: []string{"keyword:cdn"},
		Proxy:  []string{"geosite:glitch-test", "process:app.exe"},
	}, map[string][]string{"www.glitch.test": {"198.51.100.200"}, "cdn.example.test": {"198.51.100.77"}}, []tierFlow{
		{"geosite name sniffed on a blocked geoip address", app, "203.0.113.9", "www.glitch.test",
			map[string]string{"AsIs": toBlock, "IPIfNonMatch": toBlock, "IPOnDemand": toProxy}},
		{"geosite name", app, "www.glitch.test", "", everyStrategy(toProxy)},
		{"keyword name sniffed on a blocked address", app, "198.51.100.77", "cdn.example.test", everyStrategy(toBlock)},
		{"keyword name resolving to a blocked address", app, "cdn.example.test", "",
			map[string]string{"AsIs": toDirect, "IPIfNonMatch": toDirect, "IPOnDemand": toBlock}},
		{"keyword name sniffed elsewhere", app, "192.0.2.50", "cdn.example.test",
			map[string]string{"AsIs": toDirect, "IPIfNonMatch": toDirect, "IPOnDemand": toBlock}},
		{"per-app geosite name sniffed on a blocked geoip address", force, "203.0.113.9", "www.glitch.test",
			map[string]string{"AsIs": toBlock, "IPIfNonMatch": toBlock, "IPOnDemand": toProxy}},
	})
}

// A block yields only to a more specific entry of its own plane: a name entry
// does not take a flow from an address block, nor an address entry from a
// name block. Under IPOnDemand a sniffed name is judged by the address it
// resolves to; under IPIfNonMatch a name meets the name entries before it is
// resolved, as it did before tiers were ordered.
func TestApply_NameDoesNotBeatAnAddressBlock(t *testing.T) {
	app, force := AppTrafficTag, ForceProxyTag
	routeTierFlows(t, routing.Tier{
		Block:  []string{"192.0.2.0/24"},
		Direct: []string{"domain:x.test"},
		Proxy:  []string{"process:app.exe"},
	}, map[string][]string{"x.test": {"192.0.2.10"}, "www.x.test": {"198.51.100.9"}}, []tierFlow{
		{"named site sniffed on a blocked address", app, "192.0.2.10", "x.test", everyStrategy(toBlock)},
		{"blocked address", app, "192.0.2.10", "", everyStrategy(toBlock)},
		{"named site resolving to a blocked address", app, "x.test", "",
			map[string]string{"AsIs": toDirect, "IPIfNonMatch": toDirect, "IPOnDemand": toBlock}},
		{"named site elsewhere", app, "www.x.test", "", everyStrategy(toDirect)},
		{"per-app named site sniffed on a blocked address", force, "192.0.2.10", "x.test", everyStrategy(toBlock)},
	})
}

func TestApply_AddressDoesNotBeatANameBlock(t *testing.T) {
	app, force := AppTrafficTag, ForceProxyTag
	routeTierFlows(t, routing.Tier{
		Block:  []string{"keyword:ads", "geosite:ads-test"},
		Direct: []string{"192.0.2.128/25"},
		Proxy:  []string{"process:app.exe"},
	}, map[string][]string{"myads.example": {"192.0.2.200"}, "www.ads.test": {"192.0.2.200"}, "clean.test": {"192.0.2.200"}}, []tierFlow{
		{"keyword-blocked name sniffed in the direct range", app, "192.0.2.200", "myads.example", everyStrategy(toBlock)},
		{"geosite-blocked name sniffed in the direct range", app, "192.0.2.200", "www.ads.test", everyStrategy(toBlock)},
		{"address in the direct range", app, "192.0.2.200", "", everyStrategy(toDirectByAddress)},
		{"clean name sniffed in the direct range", app, "192.0.2.200", "clean.test", everyStrategy(toDirectByAddress)},
		{"per-app blocked name sniffed in the direct range", force, "192.0.2.200", "www.ads.test", everyStrategy(toBlock)},
	})
}

// With an exception in each plane, a flow takes a direct exception only where
// no block of the other plane holds it.
func TestApply_ExceptionsInBothPlanes(t *testing.T) {
	app := AppTrafficTag
	routeTierFlows(t, routing.Tier{
		Block:  []string{"geosite:ads-test", "geoip:cn"},
		Direct: []string{"full:good.ads.test", "203.0.113.7"},
		Proxy:  []string{"process:app.exe"},
	}, map[string][]string{"good.ads.test": {"203.0.113.7"}, "www.ads.test": {"203.0.113.7"}, "clean.test": {"198.51.100.9"}}, []tierFlow{
		{"name exception", app, "good.ads.test", "", everyStrategy(toDirect)},
		{"address exception", app, "203.0.113.7", "", everyStrategy(toDirectByAddress)},
		{"both exceptions", app, "203.0.113.7", "good.ads.test", everyStrategy(toDirect)},
		{"name exception sniffed on a blocked address", app, "203.0.113.9", "good.ads.test",
			map[string]string{"AsIs": toBlock, "IPIfNonMatch": toBlock, "IPOnDemand": toDirect}},
		{"blocked name sniffed on the address exception", app, "203.0.113.7", "www.ads.test", everyStrategy(toBlock)},
		{"clean name sniffed on the address exception", app, "203.0.113.7", "clean.test",
			map[string]string{"AsIs": toDirectByAddress, "IPIfNonMatch": toDirectByAddress, "IPOnDemand": toCatchAll}},
	})
}
