//go:build !no_mihomo && !no_xray && with_tun2socks

package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/hub/executor"
	mihomoLog "github.com/metacubex/mihomo/log"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// sniffedFlow opens a flow to dst and speaks first the way an app does, with
// the name in a TLS ClientHello on 443 or an HTTP Host header on 80.
func sniffedFlow(t *testing.T, p t2sproxy.Proxy, dst net.IP, port int, name string) {
	t.Helper()
	conn, err := p.DialContext(context.Background(), bridgeTestFlow(M.TCP, &net.TCPAddr{IP: dst, Port: port}))
	if err != nil {
		t.Fatalf("dial %s:%d: %v", dst, port, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if port == 80 {
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + name + "\r\n\r\n"))
		return
	}
	go func() { _ = tls.Client(conn, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake() }()
}

// A flow addressed by an IP carries its name in its first bytes. With sniffing
// on, mihomo must route such a flow by that name, without dialing anything but
// the address it was given; a name that DNS supplied stays the flow's name.
func TestMihomoBridge_SniffsFlowsAddressedByIP(t *testing.T) {
	skipWhereMihomoRaces(t)
	for _, localNetworks := range []bool{true, false} {
		t.Run(fmt.Sprintf("localNetworks=%v", localNetworks), func(t *testing.T) {
			mihomoTestHome(t)
			t.Cleanup(mihomoTeardown)

			proxied := make(chan string, 8)
			socksPort := socksRecorder(t, proxied)
			direct := make(chan string, 8)
			// Loopback is a local network: with them off it is as public as any
			// address and, unlike one, a listener can stand on it.
			lan := net.ParseIP("127.0.0.5")
			pinned := net.ParseIP("127.0.0.9")
			public := net.ParseIP("203.0.113.7")
			stale := net.ParseIP("198.19.250.250")
			for _, host := range []net.IP{lan, pinned} {
				for _, port := range []int{80, 443} {
					listenDirect(t, host, port, direct, nil)
				}
			}

			// A tier that comes after direct.test blocks pinned's address.
			prof := routing.Profile{
				Mode:          routing.ModeProxyAll,
				LocalNetworks: localNetworks,
				Tiers: []routing.Tier{
					{Block: []string{"domain:blocked.test"}, Direct: []string{"domain:direct.test"}},
					{Block: []string{pinned.String() + "/32"}},
				},
			}
			dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"127.0.0.1:1"}}
			cfg, err := mihomoconfig.BuildConfig([]string{bridgeTestVlessLink},
				mihomoconfig.Inbound{Bridge: true, ForceProxy: true, DNS: dns}, mihomoconfig.Options{}, prof)
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

			routed := mihomoLog.Subscribe()
			t.Cleanup(func() { mihomoLog.UnSubscribe(routed) })
			x := &CoreController{}
			mark := x.sessionGen.Load()
			app := &mihomoBridgeProxy{x: x, mark: mark}
			force := &mihomoBridgeProxy{x: x, mark: mark, inName: mihomoconfig.ForceProxyInName}

			fake := fakeIPFor(t, "fake.test")
			fakeBlocked := fakeIPFor(t, "blocked.test")
			if !strings.HasPrefix(fake.String(), "198.19.") {
				t.Fatalf("fake-ip %s, want 198.19.0.0/16", fake)
			}

			// mihomo logs a fake-ip flow by its restored name, any other by address.
			restored := map[string]string{fake.String(): "fake.test", fakeBlocked.String(): "blocked.test"}
			remoteOf := func(ip net.IP) string {
				if name, ok := restored[ip.String()]; ok {
					return name
				}
				return ip.String()
			}
			lanDirect, onLAN := "direct:"+lan.String(), "proxy:"+lan.String()
			if localNetworks {
				onLAN = lanDirect
			}
			blockedLAN := "block"
			if localNetworks {
				blockedLAN = lanDirect
			}
			directTierLAN := map[bool]string{true: lanDirect, false: "proxy:" + lan.String()}[localNetworks]
			// With local networks on the address is never sniffed, so its own
			// block applies.
			pinnedApp, pinnedForce := "block", "block"
			if !localNetworks {
				pinnedApp = "direct:" + pinned.String()
			}
			proxyPublic := "proxy:" + public.String()
			flows := []struct {
				what     string
				dst      net.IP
				port     int
				name     string
				app, frc string
			}{
				{"public IP, blocked name, TLS", public, 443, "blocked.test", "block", "block"},
				{"public IP, blocked name, HTTP", public, 80, "blocked.test", "block", "block"},
				{"public IP, other name, TLS", public, 443, "other.test", proxyPublic, proxyPublic},
				{"public IP, other name, HTTP", public, 80, "other.test", proxyPublic, proxyPublic},
				// With local networks off the loopback listener is a public address.
				{"listening IP, blocked name, TLS", lan, 443, "blocked.test", blockedLAN, blockedLAN},
				{"listening IP, direct-tier name, TLS", lan, 443, "direct.test", lanDirect, directTierLAN},
				{"listening IP, direct-tier name, HTTP", lan, 80, "direct.test", lanDirect, directTierLAN},
				{"listening IP, other name, TLS", lan, 443, "other.test", onLAN, onLAN},
				{"LAN IP, nas.local, TLS", lan, 443, "nas.local", onLAN, onLAN},
				{"LAN IP, nas.local, HTTP", lan, 80, "nas.local", onLAN, onLAN},
				// The address is blocked by a later tier than the name's direct
				// rule. Today the name's rule wins for a normal flow and the dial
				// reaches the blocked address; a force-proxy flow meets every
				// block first. Which should win is a product decision.
				{"blocked IP, direct-tier SNI, TLS", pinned, 443, "direct.test", pinnedApp, pinnedForce},
				// An address in the fake pool with no record behind it.
				{"stale fake-ip, direct-tier SNI", stale, 443, "direct.test", "block", "block"},
				{"fake-ip of fake.test, TLS", fake, 443, "fake.test", "proxy:fake.test", "proxy:fake.test"},
				// The restored name is the flow's name; the bytes cannot rename it.
				{"fake-ip of fake.test, SNI blocked.test", fake, 443, "blocked.test", "proxy:fake.test", "proxy:fake.test"},
				{"fake-ip of blocked.test, SNI other.test", fakeBlocked, 443, "other.test", "block", "block"},
			}
			for _, side := range []struct {
				name  string
				proxy t2sproxy.Proxy
			}{{"app", app}, {"force", force}} {
				for _, f := range flows {
					want := f.app
					if side.name == "force" {
						want = f.frc
					}
					t.Run(side.name+"/"+f.what, func(t *testing.T) {
						drain(proxied)
						drain(direct)
						for len(routed) > 0 {
							<-routed
						}
						sniffedFlow(t, side.proxy, f.dst, f.port, f.name)
						if got := flowOutcome(t, remoteOf(f.dst), f.port, proxied, direct, routed); got != want {
							t.Fatalf("went %s, want %s", got, want)
						}
						if want == "block" {
							select {
							case s := <-direct:
								t.Fatalf("a blocked flow still reached %s", s)
							case <-time.After(300 * time.Millisecond):
							}
						}
					})
				}
			}
		})
	}
}
