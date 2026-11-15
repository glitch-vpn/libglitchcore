//go:build !no_mihomo && !no_xray

package core

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/hub/executor"
	D "github.com/miekg/dns"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// bridgeNormalModeQuery sends one app query through the bridge with fake-ip
// off: the general resolver sits behind a socks recorder standing in for the
// target, the direct one on loopback, and each reports what reached it.
func bridgeNormalModeQuery(t *testing.T, prof routing.Profile, withDirect bool, name string) (proxied, fromDevice <-chan string) {
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
	listenDirect(t, net.IPv4(127, 0, 0, 1), generalPort, device)
	listenDirect(t, net.IPv4(127, 0, 0, 2), directPort, device)
	seen := make(chan string, 8)
	socksPort := socksRecorder(t, seen)

	dns := dnsconfig.Config{Mode: dnsconfig.ModeNormal, Servers: []string{"tcp://127.0.0.1:" + strconv.Itoa(generalPort)}}
	if withDirect {
		dns.DirectServers = []string{"tcp://127.0.0.2:" + strconv.Itoa(directPort)}
	}
	in, _ := mihomoBridgeInbound(&dns, prof)
	cfg, err := mihomoconfig.BuildConfig([]string{bridgeTestVlessLink}, in, mihomoconfig.Options{}, prof)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	target := mihomoconfig.Target([]string{bridgeTestVlessLink})
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
	q.SetQuestion(name+".", D.TypeA)
	query, _ := q.Pack()
	if _, err := pc.WriteTo(query, resolver); err != nil {
		t.Fatal(err)
	}
	return seen, device
}

func requireQueryTravels(t *testing.T, proxied, fromDevice <-chan string, want string) {
	t.Helper()
	select {
	case seen := <-proxied:
		if want != seen {
			t.Fatalf("the proxy carried %s, want %s", seen, want)
		}
	case seen := <-fromDevice:
		if want != seen {
			t.Fatalf("%s was reached from the device's own address, want %s", seen, want)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the query reached neither the proxy nor a resolver")
	}
	select {
	case seen := <-fromDevice:
		t.Fatalf("%s was also reached from the device's own address", seen)
	case <-time.After(time.Second):
	}
}

// With fake-ip off the bridge hands an app's query to mihomo's resolver, and
// the resolver reaches its upstream through the proxy, never from the
// device's own address.
func TestMihomoBridge_NormalModeQueriesTravelThroughTheProxy(t *testing.T) {
	skipWhereMihomoRaces(t)
	proxied, fromDevice := bridgeNormalModeQuery(t, routing.Profile{Mode: routing.ModeProxyAll}, false, "outside.test")
	requireQueryTravels(t, proxied, fromDevice, "proxy:127.0.0.1")
}

// A name under an earlier tier's broader proxied suffix is proxied by that
// tier, and its query takes the proxied path too, though a later tier names
// it direct: mihomo answers from the deepest suffix it is given, so the
// narrower direct name is kept out of the policy.
func TestMihomoBridge_NormalModeQueryFollowsTheEarlierTier(t *testing.T) {
	skipWhereMihomoRaces(t)
	prof := routing.Profile{Mode: routing.ModeProxyAll, Tiers: []routing.Tier{{Proxy: []string{"domain:ru"}}, {Direct: []string{"domain:vk.ru"}}}}
	proxied, fromDevice := bridgeNormalModeQuery(t, prof, true, "vk.ru")
	requireQueryTravels(t, proxied, fromDevice, "proxy:127.0.0.1")

	// The other way round the direct name's rule comes first, and its query
	// goes to the direct resolver.
	prof = routing.Profile{Mode: routing.ModeProxyAll, Tiers: []routing.Tier{{Direct: []string{"domain:vk.ru"}}, {Proxy: []string{"domain:ru"}}}}
	proxied, fromDevice = bridgeNormalModeQuery(t, prof, true, "vk.ru")
	requireQueryTravels(t, proxied, fromDevice, "direct:127.0.0.2")
}
