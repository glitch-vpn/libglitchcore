//go:build !no_mihomo && !no_xray

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
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/hub/executor"
	mihomoLog "github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// fakeIPFor asks mihomo's resolver for name, which allocates its fake-ip.
func fakeIPFor(t *testing.T, name string) net.IP {
	t.Helper()
	q := new(D.Msg)
	q.SetQuestion(name+".", D.TypeA)
	packed, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out, err := resolver.RelayDnsPacket(context.Background(), packed, make([]byte, 4096))
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	var answer D.Msg
	if err := answer.Unpack(out); err != nil || len(answer.Answer) == 0 {
		t.Fatalf("resolve %s: %v, %v", name, answer.Answer, err)
	}
	return answer.Answer[0].(*D.A).A
}

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

// What mihomo did with a flow: "proxy:<destination>" as the recorder behind
// the proxy saw it, "block" or "direct" as mihomo's own routing line for the
// flow's address says.
func flowOutcome(t *testing.T, remote string, port int, proxied <-chan string, routed <-chan mihomoLog.Event) string {
	t.Helper()
	addr := net.JoinHostPort(remote, fmt.Sprint(port))
	deadline := time.After(10 * time.Second)
	for {
		select {
		case s := <-proxied:
			return s
		case ev := <-routed:
			if !strings.Contains(ev.Payload, addr) {
				continue
			}
			switch {
			case strings.Contains(ev.Payload, "REJECT"):
				return "block"
			case strings.Contains(ev.Payload, "DIRECT"):
				return "direct"
			}
		case <-deadline:
			return "none"
		}
	}
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
			lan := net.ParseIP("127.0.0.5")
			public := net.ParseIP("203.0.113.7")
			for _, port := range []int{80, 443} {
				listenDirect(t, lan, port, direct)
			}

			prof := routing.Profile{
				Mode:          routing.ModeProxyAll,
				LocalNetworks: localNetworks,
				Tiers: []routing.Tier{{
					Block:  []string{"domain:blocked.test"},
					Direct: []string{"domain:direct.test"},
				}},
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
			lanWant := map[bool]string{true: "direct", false: "proxy:" + lan.String()}[localNetworks]
			flows := []struct {
				what     string
				dst      net.IP
				port     int
				name     string
				app, frc string
			}{
				{"public IP, blocked name, TLS", public, 443, "blocked.test", "block", "block"},
				{"public IP, blocked name, HTTP", public, 80, "blocked.test", "block", "block"},
				{"public IP, direct-tier name, TLS", public, 443, "direct.test", "direct", "proxy:" + public.String()},
				{"public IP, other name, TLS", public, 443, "other.test", "proxy:" + public.String(), "proxy:" + public.String()},
				{"public IP, other name, HTTP", public, 80, "other.test", "proxy:" + public.String(), "proxy:" + public.String()},
				{"LAN IP, nas.local, TLS", lan, 443, "nas.local", lanWant, lanWant},
				{"LAN IP, nas.local, HTTP", lan, 80, "nas.local", lanWant, lanWant},
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
						if got := flowOutcome(t, remoteOf(f.dst), f.port, proxied, routed); got != want {
							t.Fatalf("went %s, want %s", got, want)
						}
						if want == "direct" && f.dst.Equal(lan) {
							select {
							case <-direct:
							case <-time.After(5 * time.Second):
								t.Fatal("a direct flow never reached the listener")
							}
						}
					})
				}
			}
		})
	}
}

func drain(c <-chan string) {
	for len(c) > 0 {
		<-c
	}
}

func listenDirect(t *testing.T, host net.IP, port int, seen chan<- string) {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host.String(), fmt.Sprint(port)))
	if err != nil {
		t.Skipf("listen on %s:%d: %v", host, port, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			seen <- "direct:" + host.String()
			go func() {
				buf := make([]byte, 512)
				for {
					if _, err := c.Read(buf); err != nil {
						_ = c.Close()
						return
					}
				}
			}()
		}
	}()
}
