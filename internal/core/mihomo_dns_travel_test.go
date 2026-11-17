//go:build !no_mihomo && !no_xray && with_tun2socks

package core

import (
	"net"
	"strconv"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/hub/executor"
	D "github.com/miekg/dns"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// bridgeQuery sends one app query through the bridge: the general resolver
// sits behind a socks recorder standing in for the target, the direct one on
// loopback, and each reports what reached it.
func bridgeQuery(t *testing.T, dns dnsconfig.Config, prof routing.Profile, withDirect bool, name string, qtype uint16) (proxied, fromDevice <-chan string) {
	t.Helper()
	mihomoTestHome(t)
	t.Cleanup(mihomoTeardown)

	generalPort, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	directPort, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	device := make(chan string, 8)
	listenDirect(t, net.IPv4(127, 0, 0, 1), generalPort, device, nil)
	listenDirect(t, net.IPv4(127, 0, 0, 2), directPort, device, nil)
	seen := make(chan string, 8)
	socksPort := socksRecorder(t, seen)

	dns.Servers = []string{"tcp://127.0.0.1:" + strconv.Itoa(generalPort)}
	if withDirect {
		dns.DirectServers = []string{"tcp://127.0.0.2:" + strconv.Itoa(directPort)}
	}
	in, _ := mihomoBridgeInbound(&dns, prof)
	cfg, err := mihomoconfig.BuildConfig([]string{vlessTestLink}, in, mihomoconfig.Options{}, prof)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	target := mihomoconfig.Target([]string{vlessTestLink})
	recorder, err := adapter.ParseProxy(map[string]any{"name": target, "type": "socks5", "server": "127.0.0.1", "port": socksPort})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Proxies[target] = recorder
	executor.ApplyConfig(cfg, true)

	x := &CoreController{}
	app := &mihomoBridgeProxy{x: x, mark: x.sessionGen.Load()}
	resolver := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
	pc, err := app.DialUDP(bridgeTestFlow(M.UDP, resolver))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	q := new(D.Msg)
	q.SetQuestion(name+".", qtype)
	query, _ := q.Pack()
	if _, err := pc.WriteTo(query, resolver); err != nil {
		t.Fatal(err)
	}
	return seen, device
}

// With fake-ip off the bridge hands an app's query to mihomo's resolver, and
// the resolver reaches its upstream through the proxy, never from the
// device's own address.
func TestMihomoBridge_NormalModeQueriesTravelThroughTheProxy(t *testing.T) {
	skipWhereMihomoRaces(t)
	proxied, fromDevice := bridgeQuery(t, normalMode, routing.Profile{Mode: routing.ModeProxyAll}, false, "outside.test", D.TypeA)
	requireQueryTravels(t, proxied, fromDevice, "proxy:127.0.0.1")
}

// A name under an earlier tier's broader proxied suffix is proxied by that
// tier, and its query takes the proxied path too, though a later tier names
// it direct: mihomo answers from the deepest suffix it is given, so the
// narrower direct name is kept out of the policy.
func TestMihomoBridge_NormalModeQueryFollowsTheEarlierTier(t *testing.T) {
	skipWhereMihomoRaces(t)
	prof := routing.Profile{Mode: routing.ModeProxyAll, Tiers: []routing.Tier{{Proxy: []string{"domain:ru"}}, {Direct: []string{"domain:vk.ru"}}}}
	proxied, fromDevice := bridgeQuery(t, normalMode, prof, true, "vk.ru", D.TypeA)
	requireQueryTravels(t, proxied, fromDevice, "proxy:127.0.0.1")

	// The other way round the direct name's rule comes first, and its query
	// goes to the direct resolver.
	prof = routing.Profile{Mode: routing.ModeProxyAll, Tiers: []routing.Tier{{Direct: []string{"domain:vk.ru"}}, {Proxy: []string{"domain:ru"}}}}
	proxied, fromDevice = bridgeQuery(t, normalMode, prof, true, "vk.ru", D.TypeA)
	requireQueryTravels(t, proxied, fromDevice, "direct:127.0.0.2")
}

// With fake-ip on, a name kept off the pool by the filter goes upstream as
// its flow would: through the proxy where the catch-all proxies, to the
// direct resolver where a tier sends the name direct. A record type the pool
// does not answer goes upstream the same way, whatever the name.
func TestMihomoBridge_FakeIPUpstreamQueriesTravelWithTheirFlows(t *testing.T) {
	skipWhereMihomoRaces(t)
	filtered := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, FakeIPFilter: []string{"outside.test", "vk.ru"}}
	proxyAll := routing.Profile{Mode: routing.ModeProxyAll, Tiers: []routing.Tier{{Direct: []string{"domain:ru"}}}}

	proxied, fromDevice := bridgeQuery(t, filtered, proxyAll, true, "outside.test", D.TypeA)
	requireQueryTravels(t, proxied, fromDevice, "proxy:127.0.0.1")

	proxied, fromDevice = bridgeQuery(t, filtered, proxyAll, true, "vk.ru", D.TypeA)
	requireQueryTravels(t, proxied, fromDevice, "direct:127.0.0.2")

	proxied, fromDevice = bridgeQuery(t, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP}, proxyAll, true, "anything.test", D.TypeTXT)
	requireQueryTravels(t, proxied, fromDevice, "proxy:127.0.0.1")
}
