//go:build !no_mihomo && !no_xray

package core

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	mihomoLog "github.com/metacubex/mihomo/log"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// nativeTunFlow hands mihomo's tunnel a TCP flow the way its own TUN listener
// does, from an app with the given name.
func nativeTunFlow(t *testing.T, dst net.IP, port int, app string) {
	t.Helper()
	local, engine := net.Pipe()
	t.Cleanup(func() { _ = local.Close() })
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.TUN,
		SrcIP:   netip.MustParseAddr("198.18.0.1"),
		SrcPort: 40000,
		DstPort: uint16(port),
		Process: app,
	}
	metadata.DstIP, _ = netip.AddrFromSlice(dst.To4())
	go mihomoTunnel.Tunnel.HandleTCPConn(engine, metadata)
}

// mihomo's own TUN, with the settings the core gives the desktop adapter, routes
// by the app behind a flow, in the order the bridge gave those apps: a flow of
// an app sent direct meets the blocks; a name from the core's resolver is the
// flow's name.
func TestMihomoNativeTun_RoutesByAppAndByName(t *testing.T) {
	skipWhereMihomoRaces(t)
	mihomoTestHome(t)
	t.Cleanup(mihomoTeardown)

	proxied := make(chan string, 8)
	socksPort := socksRecorder(t, proxied)
	direct := make(chan string, 8)
	host := net.ParseIP("127.0.0.5")
	listenDirect(t, host, 443, direct, nil)

	prof := routing.Profile{
		Mode: routing.ModeDirectAll,
		Tiers: []routing.Tier{
			{Direct: []string{"process:direct.exe"}},
			{Block: []string{"domain:blocked.test", "127.0.0.5/32"}, Proxy: []string{"process:tunneled.exe"}},
		},
	}
	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"127.0.0.1:1"}}
	inbound := mihomoconfig.Inbound{Tun: mihomoTunInbound(dns, -1)}
	cfg, err := mihomoconfig.BuildConfig([]string{vlessTestLink}, inbound, mihomoconfig.Options{}, prof)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	// No adapter in a test: the listener is off, the tunnel is fed by hand.
	cfg.General.Tun.Enable = false
	cfg.General.FindProcessMode = process.FindProcessOff
	target := mihomoconfig.Target([]string{vlessTestLink})
	recorder, err := adapter.ParseProxy(map[string]any{"name": target, "type": "socks5", "server": "127.0.0.1", "port": socksPort})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Proxies[target] = recorder
	applyMihomoConfig(cfg, inbound, false, prof)

	routed := mihomoLog.Subscribe()
	t.Cleanup(func() { mihomoLog.UnSubscribe(routed) })

	fake := fakeIPFor(t, "fake.test")
	fakeBlocked := fakeIPFor(t, "blocked.test")
	if !strings.HasPrefix(fake.String(), "198.18.") {
		t.Fatalf("fake-ip %s, want the native pool 198.18.0.0/16", fake)
	}
	flows := []struct {
		what   string
		dst    net.IP
		remote string
		app    string
		want   string
	}{
		{"other app, blocked address", host, "127.0.0.5", "browser.exe", "block"},
		{"direct app, address a later tier blocks", host, "127.0.0.5", "direct.exe", "block"},
		{"direct app, blocked name", fakeBlocked, "blocked.test", "direct.exe", "block"},
		{"other app, blocked name", fakeBlocked, "blocked.test", "browser.exe", "block"},
		{"tunneled app, name the resolver gave, in direct-all mode", fake, "fake.test", "tunneled.exe", "proxy:fake.test"},
	}
	for _, f := range flows {
		t.Run(f.what, func(t *testing.T) {
			drain(proxied)
			drain(direct)
			for len(routed) > 0 {
				<-routed
			}
			nativeTunFlow(t, f.dst, 443, f.app)
			if got := flowOutcome(t, f.remote, 443, proxied, direct, routed); got != f.want {
				t.Fatalf("went %s, want %s", got, f.want)
			}
		})
	}
}

// An address block meets a name an app sent direct arrives as: the name is
// looked up at the direct resolvers and the flow is refused when an address
// they give is blocked, or when they cannot answer. A name whose addresses are
// all open is dialled direct at them.
func TestMihomoNativeTun_DirectAppNamedFlowMeetsAddressBlocks(t *testing.T) {
	skipWhereMihomoRaces(t)
	mihomoTestHome(t)
	t.Cleanup(mihomoTeardown)

	proxied := make(chan string, 8)
	socksPort := socksRecorder(t, proxied)
	direct := make(chan string, 8)
	openHost := net.ParseIP("127.0.0.6")
	listenDirect(t, openHost, 443, direct, nil)
	resolverPort, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	listenDirect(t, net.IPv4(127, 0, 0, 2), resolverPort, nil, answerOverTCP(map[string][]net.IP{
		"blocked-address.test": {net.ParseIP("203.0.113.7")},
		"mixed-address.test":   {openHost, net.ParseIP("203.0.113.8")},
		"open-address.test":    {openHost},
	}))

	prof := routing.Profile{
		Mode: routing.ModeProxyAll,
		Tiers: []routing.Tier{
			{Direct: []string{"process:direct.exe"}},
			{Block: []string{"203.0.113.0/24"}},
		},
	}
	dns := dnsconfig.Config{
		Mode:          dnsconfig.ModeFakeIP,
		Servers:       []string{"127.0.0.1:1"},
		DirectServers: []string{"tcp://127.0.0.2:" + strconv.Itoa(resolverPort)},
	}
	inbound := mihomoconfig.Inbound{Tun: mihomoTunInbound(dns, -1)}
	cfg, err := mihomoconfig.BuildConfig([]string{vlessTestLink}, inbound, mihomoconfig.Options{}, prof)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	cfg.General.Tun.Enable = false
	cfg.General.FindProcessMode = process.FindProcessOff
	target := mihomoconfig.Target([]string{vlessTestLink})
	recorder, err := adapter.ParseProxy(map[string]any{"name": target, "type": "socks5", "server": "127.0.0.1", "port": socksPort})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Proxies[target] = recorder
	applyMihomoConfig(cfg, inbound, false, prof)

	routed := mihomoLog.Subscribe()
	t.Cleanup(func() { mihomoLog.UnSubscribe(routed) })

	for _, f := range []struct{ name, want string }{
		{"blocked-address.test", "block"},
		{"mixed-address.test", "block"},
		{"unresolvable.test", "block"},
		{"open-address.test", "direct:" + openHost.String()},
	} {
		t.Run(f.name, func(t *testing.T) {
			drain(proxied)
			drain(direct)
			for len(routed) > 0 {
				<-routed
			}
			nativeTunFlow(t, fakeIPFor(t, f.name), 443, "direct.exe")
			if got := flowOutcome(t, f.name, 443, proxied, direct, routed); got != f.want {
				t.Fatalf("went %s, want %s", got, f.want)
			}
		})
	}
}
