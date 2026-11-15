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

// With fake-ip off the bridge hands an app's query to mihomo's resolver, and
// the resolver reaches its upstream through the proxy, never from the
// device's own address.
func TestMihomoBridge_NormalModeQueriesTravelThroughTheProxy(t *testing.T) {
	skipWhereMihomoRaces(t)
	mihomoTestHome(t)
	t.Cleanup(mihomoTeardown)

	upstreamPort, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	fromDevice := make(chan string, 8)
	listenDirect(t, net.IPv4(127, 0, 0, 1), upstreamPort, fromDevice)
	proxied := make(chan string, 8)
	socksPort := socksRecorder(t, proxied)

	prof := routing.Profile{Mode: routing.ModeProxyAll}
	dns := dnsconfig.Config{Mode: dnsconfig.ModeNormal, Servers: []string{"tcp://127.0.0.1:" + strconv.Itoa(upstreamPort)}}
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
	defer pc.Close()
	q := new(D.Msg)
	q.SetQuestion("outside.test.", D.TypeA)
	query, _ := q.Pack()
	if _, err := pc.WriteTo(query, resolver); err != nil {
		t.Fatal(err)
	}

	select {
	case seen := <-proxied:
		if seen != "proxy:127.0.0.1" {
			t.Fatalf("the proxy carried %s, want the upstream resolver", seen)
		}
	case seen := <-fromDevice:
		t.Fatalf("the upstream resolver was reached %s, from the device's own address", seen)
	case <-time.After(15 * time.Second):
		t.Fatal("the query reached neither the proxy nor the resolver")
	}
	select {
	case seen := <-fromDevice:
		t.Fatalf("the upstream resolver was reached %s, from the device's own address", seen)
	case <-time.After(time.Second):
	}
}
