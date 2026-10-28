//go:build !no_xray

package core

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	D "github.com/miekg/dns"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	xrayCore "github.com/xtls/xray-core/core"
	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
)

// socksRecorder is a SOCKS5 server that reports the destination of each
// CONNECT as "proxy:<dst>" and then holds the connection open.
func socksRecorder(t *testing.T, seen chan<- string) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				b := make([]byte, 262)
				if _, err := io.ReadFull(c, b[:2]); err != nil {
					return
				}
				_, _ = io.ReadFull(c, b[:b[1]])
				_, _ = c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, b[:4]); err != nil {
					return
				}
				var dst string
				switch b[3] {
				case 1:
					_, _ = io.ReadFull(c, b[:4])
					dst = net.IP(b[:4]).String()
				case 3:
					_, _ = io.ReadFull(c, b[:1])
					n := int(b[0])
					_, _ = io.ReadFull(c, b[:n])
					dst = string(b[:n])
				case 4:
					_, _ = io.ReadFull(c, b[:16])
					dst = net.IP(b[:16]).String()
				}
				_, _ = io.ReadFull(c, b[:2])
				seen <- "proxy:" + dst
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// directRecorder listens on a loopback address of its own and reports each
// connection as "direct:<host>".
func directRecorder(t *testing.T, host string, seen chan<- string) int {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("listen on %s: %v", host, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			seen <- "direct:" + host
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// startSniffInstance runs xray with the proxy outbound replaced by a SOCKS
// client to the recorder, so where a flow went is observable.
func startSniffInstance(t *testing.T, prof routing.Profile, socksPort int) *xrayCore.Instance {
	t.Helper()
	res, err := xrayconfig.BuildConfig([]string{bridgeTestVlessLink}, xrayconfig.BalancerOptions{}, prof, "none")
	if err != nil {
		t.Fatal(err)
	}
	for i := range res.Config.OutboundConfigs {
		if res.Config.OutboundConfigs[i].Tag == res.RouteTarget {
			settings := json.RawMessage(fmt.Sprintf(`{"servers":[{"address":"127.0.0.1","port":%d}]}`, socksPort))
			res.Config.OutboundConfigs[i] = xrayConf.OutboundDetourConfig{Protocol: "socks", Tag: res.RouteTarget, Settings: &settings}
		}
	}
	xrayconfig.ApplyDNS(res.Config, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"127.0.0.1:1"}}, prof)
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

// fakeAnswer asks the instance's fake DNS for name and returns the fake IP.
func fakeAnswer(t *testing.T, p *xrayBridgeProxy, name string, qtype uint16) net.IP {
	t.Helper()
	resolver := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
	pc, err := p.DialUDP(bridgeTestFlow(M.UDP, resolver))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	q := new(D.Msg)
	q.SetQuestion(name+".", qtype)
	query, _ := q.Pack()
	buf := make([]byte, 2048)
	for i := 0; i < 10; i++ {
		_, _ = pc.WriteTo(query, resolver)
		_ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		r := new(D.Msg)
		if r.Unpack(buf[:n]) != nil || len(r.Answer) == 0 {
			return nil
		}
		switch a := r.Answer[0].(type) {
		case *D.A:
			return a.A
		case *D.AAAA:
			return a.AAAA
		}
	}
	return nil
}

// sniffFlow dials ip:port through the bridge proxy, sends a TLS ClientHello or
// an HTTP request naming name (or nothing), and returns where the flow ended up.
func sniffFlow(t *testing.T, p *xrayBridgeProxy, ip net.IP, port int, kind, name string, seen chan string) string {
	t.Helper()
	for len(seen) > 0 {
		<-seen
	}
	conn, err := p.DialContext(context.Background(), bridgeTestFlow(M.TCP, &net.TCPAddr{IP: ip, Port: port}))
	if err != nil {
		return "dial error: " + err.Error()
	}
	defer conn.Close()
	switch kind {
	case "tls":
		go func() {
			_ = tls.Client(conn, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
		}()
	case "http":
		_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + name + "\r\n\r\n"))
	}
	select {
	case s := <-seen:
		return s
	case <-time.After(2 * time.Second):
		return "none"
	}
}

// Content sniffing names a flow for routing, except toward the local networks
// when they go direct: a LAN device reached by its name stays on the LAN, a
// fake IP still reaches the proxy as its name, and a blocked name is blocked.
func TestXraySniffing_LocalNetworksStayDirect(t *testing.T) {
	const lanHost = "127.0.0.5"
	for _, localNetworks := range []bool{true, false} {
		t.Run(fmt.Sprintf("localNetworks=%v", localNetworks), func(t *testing.T) {
			seen := make(chan string, 8)
			socksPort := socksRecorder(t, seen)
			lanPort := directRecorder(t, lanHost, seen)
			prof := routing.Profile{
				Mode:          routing.ModeProxyAll,
				LocalNetworks: localNetworks,
				Tiers:         []routing.Tier{{Block: []string{"domain:blocked.test"}, Proxy: []string{"process:app.exe"}}},
			}
			inst := startSniffInstance(t, prof, socksPort)
			sniffing, err := xrayconfig.AppSniffing(true, prof.LocalNetworks)
			if err != nil {
				t.Fatal(err)
			}
			x := &CoreController{}
			app, err := x.newXrayBridgeProxy(inst, xrayconfig.AppTrafficTag, sniffing, x.sessionGen.Load())
			if err != nil {
				t.Fatal(err)
			}
			force, err := x.newXrayBridgeProxy(inst, xrayconfig.ForceProxyTag, sniffing, x.sessionGen.Load())
			if err != nil {
				t.Fatal(err)
			}

			wantLAN := "proxy:" + lanHost
			if localNetworks {
				wantLAN = "direct:" + lanHost
			}
			lanIP, publicIP := net.ParseIP(lanHost), net.ParseIP("198.51.100.9")
			for _, side := range []struct {
				name  string
				proxy *xrayBridgeProxy
			}{{"normal", app}, {"per-app", force}} {
				for _, kind := range []string{"tls", "http"} {
					if got := sniffFlow(t, side.proxy, lanIP, lanPort, kind, "nas.local", seen); got != wantLAN {
						t.Errorf("%s %s flow to a local IP naming nas.local -> %s, want %s", side.name, kind, got, wantLAN)
					}
				}
				if got := sniffFlow(t, side.proxy, publicIP, 443, "tls", "blocked.test", seen); got != "none" {
					t.Errorf("%s flow to a public IP naming blocked.test -> %s, want it blocked", side.name, got)
				}
				for _, fake := range []struct {
					name string
					qt   uint16
				}{{"fake4-" + side.name + ".test", D.TypeA}, {"fake6-" + side.name + ".test", D.TypeAAAA}} {
					ip := fakeAnswer(t, app, fake.name, fake.qt)
					if ip == nil {
						t.Errorf("no fake answer for %s", fake.name)
						continue
					}
					if got := sniffFlow(t, side.proxy, ip, 443, "none", "", seen); got != "proxy:"+fake.name {
						t.Errorf("%s flow to the fake IP %s of %s -> %s, want the name at the proxy", side.name, ip, fake.name, got)
					}
				}
			}
		})
	}
}
