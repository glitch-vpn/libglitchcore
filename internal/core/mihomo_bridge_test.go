//go:build !no_mihomo && !no_xray

package core

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/hub/executor"
	mihomoLog "github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// mihomo keeps cache.db open inside its home dir, so the dir outlives the test.
func mihomoTestHome(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "glitch-mihomo-bridge-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureMihomoHome(dir); err != nil {
		t.Fatal(err)
	}
}

var bridgeTestProfile = routing.Profile{Mode: routing.ModeDirectAll, Tiers: []routing.Tier{{Proxy: []string{"process:app.exe"}}}}

// startMihomoBridge applies the bridge's config and returns the proxies
// mihomoStartBridge hands tun2socks.
func startMihomoBridge(t *testing.T, x *CoreController) (app, force t2sproxy.Proxy) {
	t.Helper()
	app, force, _ = startMihomoBridgeFor(t, x, bridgeTestProfile, dnsconfig.Config{})
	return app, force
}

func startMihomoBridgeFor(t *testing.T, x *CoreController, prof routing.Profile, dns dnsconfig.Config) (app, force, direct t2sproxy.Proxy) {
	t.Helper()
	return startMihomoBridgeThrough(t, x, prof, dns, 0)
}

// startMihomoBridgeThrough stands a socks server on socksPort in for the
// target, where one is given; the test link's own server is unreachable.
func startMihomoBridgeThrough(t *testing.T, x *CoreController, prof routing.Profile, dns dnsconfig.Config, socksPort int) (app, force, direct t2sproxy.Proxy) {
	t.Helper()
	mihomoTestHome(t)
	in, b := mihomoBridgeInbound(&dns, prof)
	cfg, err := mihomoconfig.BuildConfig([]string{bridgeTestVlessLink}, in, mihomoconfig.Options{}, prof)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if socksPort > 0 {
		target := mihomoconfig.Target([]string{bridgeTestVlessLink})
		proxy, err := adapter.ParseProxy(map[string]any{"name": target, "type": "socks5", "server": "127.0.0.1", "port": socksPort})
		if err != nil {
			t.Fatal(err)
		}
		cfg.Proxies[target] = proxy
	}
	b.adoptDirectBlocks(cfg, prof)
	executor.ApplyConfig(cfg, true)
	t.Cleanup(mihomoTeardown)
	return mihomoBridgeProxies(x, b, x.sessionGen.Load())
}

// socksRelay is a SOCKS5 server that carries each CONNECT to its destination.
func socksRelay(t *testing.T) int {
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
				var host string
				switch b[3] {
				case 1:
					_, _ = io.ReadFull(c, b[:4])
					host = net.IP(b[:4]).String()
				case 3:
					_, _ = io.ReadFull(c, b[:1])
					n := int(b[0])
					_, _ = io.ReadFull(c, b[:n])
					host = string(b[:n])
				default:
					return
				}
				_, _ = io.ReadFull(c, b[:2])
				port := int(b[0])<<8 | int(b[1])
				upstream, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					return
				}
				defer upstream.Close()
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go func() { _, _ = io.Copy(upstream, c) }()
				_, _ = io.Copy(c, upstream)
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func TestMihomoBridge_CarriesTCPAndUDP(t *testing.T) {
	skipWhereMihomoRaces(t)
	app, _ := startMihomoBridge(t, &CoreController{})
	requireTCPRoundTrip(t, app, tcpEcho(t), "pingeof")

	// One app port, two destinations: tun2socks opens a flow for each, and
	// each must get its own replies.
	first, second := udpEcho(t), udpEcho(t)
	a, err := app.DialUDP(bridgeTestFlow(M.UDP, first))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer a.Close()
	b, err := app.DialUDP(bridgeTestFlow(M.UDP, second))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer b.Close()
	requireUDPRoundTrip(t, a, first, []byte("first"))
	requireUDPRoundTrip(t, b, second, []byte("second"))
	requireNoThirdPartyReply(t, app)
}

func TestMihomoBridge_AnswersTheAppsDNSInProcess(t *testing.T) {
	skipWhereMihomoRaces(t)
	app, _ := startMihomoBridge(t, &CoreController{})
	resolver := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
	pc, err := app.DialUDP(bridgeTestFlow(M.UDP, resolver))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer pc.Close()
	requireFakeIPAnswer(t, pc, resolver, "198.19.")

	conn, err := app.DialContext(context.Background(), bridgeTestFlow(M.TCP, &net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}))
	if err != nil {
		t.Fatalf("DialContext :53: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	q := new(D.Msg)
	q.SetQuestion("example.org.", D.TypeA)
	dc := &D.Conn{Conn: conn}
	if err := dc.WriteMsg(q); err != nil {
		t.Fatalf("tcp query: %v", err)
	}
	r, err := dc.ReadMsg()
	if err != nil || len(r.Answer) == 0 {
		t.Fatalf("tcp answer %v, err %v", r, err)
	}
	if a, ok := r.Answer[0].(*D.A); !ok || !strings.HasPrefix(a.A.String(), "198.19.") {
		t.Fatalf("tcp answer %v, want a fake IP", r.Answer[0])
	}
}

// Force-proxy flows reach the proxy by their IN-NAME rule even in direct-all
// mode; the test proxy is unreachable, so mihomo's dial-error line says so.
func TestMihomoBridge_ForceProxyFlowsTakeTheProxy(t *testing.T) {
	skipWhereMihomoRaces(t)
	_, force := startMihomoBridge(t, &CoreController{})
	sub := mihomoLog.Subscribe()
	defer mihomoLog.UnSubscribe(sub)
	echo := tcpEcho(t)
	conn, err := force.DialContext(context.Background(), bridgeTestFlow(M.TCP, echo))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("x"))
	deadline := time.After(15 * time.Second)
	for {
		select {
		case ev := <-sub:
			if !strings.Contains(ev.Payload, echo.String()) {
				continue
			}
			if !strings.Contains(ev.Payload, "InName/"+mihomoconfig.ForceProxyInName) {
				t.Fatalf("force-proxy flow took another rule: %s", ev.Payload)
			}
			return
		case <-deadline:
			t.Fatal("mihomo never routed the force-proxy flow")
		}
	}
}

func TestMihomoBridge_RefusesAfterItsSessionEnds(t *testing.T) {
	skipWhereMihomoRaces(t)
	x := &CoreController{}
	app, _ := startMihomoBridge(t, x)
	x.clearSessionState()
	if conn, err := app.DialContext(context.Background(), bridgeTestFlow(M.TCP, tcpEcho(t))); !errors.Is(err, errSessionEnded) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("tcp after the session ended: %v, want errSessionEnded", err)
	}
	if pc, err := app.DialUDP(bridgeTestFlow(M.UDP, udpEcho(t))); !errors.Is(err, errSessionEnded) {
		if pc != nil {
			_ = pc.Close()
		}
		t.Fatalf("udp after the session ended: %v, want errSessionEnded", err)
	}
}

func TestBridgePipe_HalfCloseKeepsTheOtherWay(t *testing.T) {
	a, b := bridgePipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_, _ = a.Write([]byte("req"))
		_ = a.CloseWrite()
	}()
	req, err := io.ReadAll(b)
	if err != nil || string(req) != "req" {
		t.Fatalf("read %q, %v; want the request then EOF", req, err)
	}
	go func() { _, _ = b.Write([]byte("resp")) }()
	resp := make([]byte, 4)
	if _, err := io.ReadFull(a, resp); err != nil || string(resp) != "resp" {
		t.Fatalf("read %q, %v after half-close; want the response", resp, err)
	}
	if _, err := a.Write([]byte("more")); err == nil {
		t.Fatal("write after CloseWrite must fail")
	}
	_ = a.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := a.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read past the deadline = %v, want a timeout", err)
	}
}

// answeringResolver serves DNS over TCP at host, answering the names given
// and reporting each connection on seen, when given.
func answeringResolver(t *testing.T, host net.IP, seen chan<- string, answers map[string][]net.IP) string {
	t.Helper()
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	listenDirect(t, host, port, seen, answerOverTCP(answers))
	return "tcp://" + net.JoinHostPort(host.String(), strconv.Itoa(port))
}

// oneAddress is answers with one A record per name.
func oneAddress(answers map[string]net.IP) map[string][]net.IP {
	out := make(map[string][]net.IP, len(answers))
	for name, ip := range answers {
		out[name] = []net.IP{ip}
	}
	return out
}

// echoAt echoes TCP at host on port, or on a port of its own when port is 0,
// and returns the port; it skips where host cannot be listened on.
func echoAt(t *testing.T, host string, port int) int {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
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
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// directFlowReaches dials dst as a process-direct flow and says whether an
// echo came back.
func directFlowReaches(t *testing.T, direct t2sproxy.Proxy, dst net.Addr) bool {
	t.Helper()
	conn, err := direct.DialContext(context.Background(), bridgeTestFlow(M.TCP, dst))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("x")); err != nil {
		return false
	}
	n, _ := conn.Read(make([]byte, 1))
	return n == 1
}

// directFlowReachesName is directFlowReaches at name's fake address.
func directFlowReachesName(t *testing.T, direct t2sproxy.Proxy, name string, port int) bool {
	t.Helper()
	return directFlowReaches(t, direct, &net.TCPAddr{IP: fakeIPFor(t, name), Port: port})
}

var blockedAddressProfile = routing.Profile{
	Mode:  routing.ModeProxyAll,
	Tiers: []routing.Tier{{Block: []string{"127.0.0.5/32"}, Direct: []string{"process:app.exe"}}},
}

// An app a rule sends direct by process still meets the blocks: its flow to a
// blocked address is refused, and one to anywhere else is dialed direct.
func TestMihomoBridge_ProcessDirectFlowsMeetTheBlocks(t *testing.T) {
	skipWhereMihomoRaces(t)
	prof := routing.Profile{
		Mode:  routing.ModeProxyAll,
		Tiers: []routing.Tier{{Block: []string{"127.0.0.2/32"}, Direct: []string{"process:app.exe"}}},
	}
	_, _, direct := startMihomoBridgeFor(t, &CoreController{}, prof, dnsconfig.Config{})
	if direct == nil {
		t.Fatal("no force-direct dialer for a process->direct rule")
	}
	if directFlowReaches(t, direct, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: echoAt(t, "127.0.0.2", 0)}) {
		t.Error("process-direct flow to a blocked address reached its server")
	}
	if !directFlowReaches(t, direct, tcpEcho(t)) {
		t.Error("process-direct flow to an unblocked address was not dialed direct")
	}
}

// A name no block names, but which resolves to an address a block holds, is
// refused for a process-direct app too. The block's lookup takes the direct
// resolvers, the general one plain with none named, so the proxy sees none
// of it.
func TestMihomoBridge_ProcessDirectFlowsMeetAddressBlocksByName(t *testing.T) {
	skipWhereMihomoRaces(t)
	dns := dnsconfig.Config{Servers: []string{answeringResolver(t, net.IPv4(127, 0, 0, 1), nil, oneAddress(map[string]net.IP{"blocked-address.test": net.IPv4(127, 0, 0, 5), "open-address.test": net.IPv4(127, 0, 0, 6)}))}}
	_, _, direct := startMihomoBridgeThrough(t, &CoreController{}, blockedAddressProfile, dns, socksRelay(t))
	port := echoAt(t, "127.0.0.6", 0)
	echoAt(t, "127.0.0.5", port)
	for name, want := range map[string]bool{"blocked-address.test": false, "open-address.test": true} {
		if got := directFlowReachesName(t, direct, name, port); got != want {
			t.Errorf("process-direct flow to %s reached its server = %v, want %v", name, got, want)
		}
	}
}

// A proxy that accepts every connection and answers nothing starves the
// session's resolver, which travels through it. The block of a process-direct
// app holds all the same: its name is resolved as DIRECT would resolve it,
// plain, and the flow is refused at once.
func TestMihomoBridge_ProcessDirectAddressBlockHoldsWhenTheProxyNeverAnswersDNS(t *testing.T) {
	skipWhereMihomoRaces(t)
	dns := dnsconfig.Config{Servers: []string{answeringResolver(t, net.IPv4(127, 0, 0, 1), nil, oneAddress(map[string]net.IP{"blocked-address.test": net.IPv4(127, 0, 0, 5)}))}}
	_, _, direct := startMihomoBridgeThrough(t, &CoreController{}, blockedAddressProfile, dns, socksRecorder(t, make(chan string, 64)))
	port := echoAt(t, "127.0.0.5", 0)
	started := time.Now()
	if directFlowReachesName(t, direct, "blocked-address.test", port) {
		t.Fatal("process-direct flow to a blocked address reached its server")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("the flow was refused after %v, want at once", elapsed)
	}
}

// The block is checked against the address DIRECT dials: the direct
// resolvers' answer, not the general ones', which travel through the proxy.
func TestMihomoBridge_ProcessDirectAddressBlockMeetsTheDirectResolversAnswer(t *testing.T) {
	skipWhereMihomoRaces(t)
	dns := dnsconfig.Config{
		Servers:       []string{answeringResolver(t, net.IPv4(127, 0, 0, 1), nil, oneAddress(map[string]net.IP{"blocked-direct.test": net.IPv4(127, 0, 0, 6), "open-direct.test": net.IPv4(127, 0, 0, 5)}))},
		DirectServers: []string{answeringResolver(t, net.IPv4(127, 0, 0, 2), nil, oneAddress(map[string]net.IP{"blocked-direct.test": net.IPv4(127, 0, 0, 5), "open-direct.test": net.IPv4(127, 0, 0, 6)}))},
	}
	_, _, direct := startMihomoBridgeThrough(t, &CoreController{}, blockedAddressProfile, dns, socksRelay(t))
	port := echoAt(t, "127.0.0.6", 0)
	echoAt(t, "127.0.0.5", port)
	if directFlowReachesName(t, direct, "blocked-direct.test", port) {
		t.Error("a name the direct resolver answers with a blocked address reached its server")
	}
	if !directFlowReachesName(t, direct, "open-direct.test", port) {
		t.Error("a name the direct resolver answers with an open address was not dialed direct")
	}
}

// A name the direct resolvers cannot answer is refused at the dial, not
// handed on to be resolved again.
func TestMihomoBridge_ProcessDirectFlowToAnUnresolvableNameIsRefused(t *testing.T) {
	skipWhereMihomoRaces(t)
	unreachable, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	dns := dnsconfig.Config{
		Servers:       []string{answeringResolver(t, net.IPv4(127, 0, 0, 1), nil, oneAddress(map[string]net.IP{"silent.test": net.IPv4(127, 0, 0, 6)}))},
		DirectServers: []string{"tcp://127.0.0.2:" + strconv.Itoa(unreachable)},
	}
	_, _, direct := startMihomoBridgeThrough(t, &CoreController{}, blockedAddressProfile, dns, socksRelay(t))
	fake := fakeIPFor(t, "silent.test")
	_, err = direct.DialContext(context.Background(), bridgeTestFlow(M.TCP, &net.TCPAddr{IP: fake, Port: 80}))
	if err == nil {
		t.Fatal("a process-direct flow to a name no direct resolver answers was accepted")
	}
	if strings.Contains(err.Error(), "silent.test") || strings.Contains(err.Error(), fake.String()) {
		t.Fatalf("the refusal names the destination: %v", err)
	}
	if _, err := direct.DialUDP(bridgeTestFlow(M.UDP, &net.UDPAddr{IP: fake, Port: 443})); err == nil {
		t.Fatal("a process-direct UDP flow to a name no direct resolver answers was accepted")
	}
}

// A process-direct UDP flow to a name an address block checks reads its
// replies as coming from the address the app sent to.
func TestMihomoBridge_ProcessDirectUDPFlowReadsItsReplies(t *testing.T) {
	skipWhereMihomoRaces(t)
	dns := dnsconfig.Config{Servers: []string{answeringResolver(t, net.IPv4(127, 0, 0, 1), nil, oneAddress(map[string]net.IP{"open-address.test": net.IPv4(127, 0, 0, 6)}))}}
	_, _, direct := startMihomoBridgeThrough(t, &CoreController{}, blockedAddressProfile, dns, socksRelay(t))
	echo := udpEchoAt(t, "127.0.0.6")
	dst := &net.UDPAddr{IP: fakeIPFor(t, "open-address.test"), Port: echo.(*net.UDPAddr).Port}
	pc, err := direct.DialUDP(bridgeTestFlow(M.UDP, dst))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("ping"), dst); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("ReadFrom = %q, %v, want the echo", buf[:n], err)
	}
	if from.String() != dst.String() {
		t.Fatalf("reply from %s, want %s", from, dst)
	}
}

// A name answered with several addresses is refused when any of them is
// blocked: DIRECT dials a TCP flow at each in turn, and a UDP flow at one of
// them, so a block checked against one address alone would be passed.
func TestMihomoBridge_ProcessDirectFlowToANameWithABlockedAddressAmongSeveralIsRefused(t *testing.T) {
	skipWhereMihomoRaces(t)
	answers := map[string][]net.IP{
		"mixed.test": {net.IPv4(127, 0, 0, 5), net.IPv4(127, 0, 0, 6)},
		"open.test":  {net.IPv4(127, 0, 0, 6), net.IPv4(127, 0, 0, 7)},
	}
	dns := dnsconfig.Config{Servers: []string{answeringResolver(t, net.IPv4(127, 0, 0, 1), nil, answers)}}
	_, _, direct := startMihomoBridgeThrough(t, &CoreController{}, blockedAddressProfile, dns, socksRelay(t))
	port := echoAt(t, "127.0.0.6", 0)
	echoAt(t, "127.0.0.5", port)
	echoAt(t, "127.0.0.7", port)
	for i := 0; i < 8; i++ {
		if directFlowReachesName(t, direct, "mixed.test", port) {
			t.Fatal("a name with a blocked address among its answers reached a server")
		}
	}
	if !directFlowReachesName(t, direct, "open.test", port) {
		t.Error("a name with open addresses only was not dialed direct")
	}
	fake := fakeIPFor(t, "mixed.test")
	_, err := direct.DialUDP(bridgeTestFlow(M.UDP, &net.UDPAddr{IP: fake, Port: port}))
	if err == nil {
		t.Error("a UDP flow to a name with a blocked address among its answers was accepted")
	} else if strings.Contains(err.Error(), "mixed.test") || strings.Contains(err.Error(), "127.0.0.5") {
		t.Errorf("the refusal names the destination: %v", err)
	}
}

// A name a block names is refused before any lookup: the direct resolver
// hears nothing of it.
func TestMihomoBridge_ProcessDirectFlowToABlockedNameIsRefusedWithoutALookup(t *testing.T) {
	skipWhereMihomoRaces(t)
	prof := routing.Profile{
		Mode:  routing.ModeProxyAll,
		Tiers: []routing.Tier{{Block: []string{"domain:named.test", "127.0.0.5/32"}, Direct: []string{"process:app.exe"}}},
	}
	asked := make(chan string, 8)
	dns := dnsconfig.Config{
		Servers:       []string{answeringResolver(t, net.IPv4(127, 0, 0, 1), nil, oneAddress(map[string]net.IP{"named.test": net.IPv4(127, 0, 0, 6)}))},
		DirectServers: []string{answeringResolver(t, net.IPv4(127, 0, 0, 2), asked, oneAddress(map[string]net.IP{"named.test": net.IPv4(127, 0, 0, 6)}))},
	}
	_, _, direct := startMihomoBridgeThrough(t, &CoreController{}, prof, dns, socksRelay(t))
	port := echoAt(t, "127.0.0.6", 0)
	if directFlowReachesName(t, direct, "named.test", port) {
		t.Fatal("a blocked name reached its server")
	}
	select {
	case <-asked:
		t.Fatal("the direct resolver was asked about a name a block names")
	case <-time.After(time.Second):
	}
}

// scriptedResolver serves DNS over TCP at host, handing each question to
// answer for its records and how long to hold the reply.
func scriptedResolver(t *testing.T, host net.IP, answer func(name string, qtype uint16) ([]D.RR, time.Duration)) string {
	t.Helper()
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	listenDirect(t, host, port, nil, func(c net.Conn) {
		for {
			var length [2]byte
			if _, err := io.ReadFull(c, length[:]); err != nil {
				return
			}
			buf := make([]byte, int(length[0])<<8|int(length[1]))
			if _, err := io.ReadFull(c, buf); err != nil {
				return
			}
			req := new(D.Msg)
			if req.Unpack(buf) != nil || len(req.Question) == 0 {
				return
			}
			q := req.Question[0]
			records, hold := answer(strings.TrimSuffix(q.Name, "."), q.Qtype)
			reply := new(D.Msg)
			reply.SetReply(req)
			reply.Answer = records
			b, err := reply.Pack()
			if err != nil {
				return
			}
			go func() {
				time.Sleep(hold)
				_, _ = c.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...))
			}()
		}
	})
	return "tcp://" + net.JoinHostPort(host.String(), strconv.Itoa(port))
}

// connectionsAt listens at host on port and counts what connects.
func connectionsAt(t *testing.T, host string, port int) *atomic.Int32 {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Skipf("listen on %s: %v", host, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var count atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			_ = c.Close()
		}
	}()
	return &count
}

// A name whose answer changes at every lookup is looked up once: the flow is
// dialed at the address the blocks were checked against, not at one a second
// lookup finds.
func TestMihomoBridge_ProcessDirectTCPFlowDialsTheCheckedAddressWhenTheAnswerChanges(t *testing.T) {
	skipWhereMihomoRaces(t)
	var lookups atomic.Int32
	answers := []net.IP{net.IPv4(127, 0, 0, 6), net.IPv4(127, 0, 0, 5)}
	server := scriptedResolver(t, net.IPv4(127, 0, 0, 1), func(name string, qtype uint16) ([]D.RR, time.Duration) {
		if name != "rotating.test" || qtype != D.TypeA {
			return nil, 0
		}
		ip := answers[int(lookups.Add(1)-1)%len(answers)]
		return []D.RR{&D.A{Hdr: D.RR_Header{Name: name + ".", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 0}, A: ip.To4()}}, 0
	})
	_, _, direct := startMihomoBridgeThrough(t, &CoreController{}, blockedAddressProfile, dnsconfig.Config{Servers: []string{server}}, socksRelay(t))
	port := echoAt(t, "127.0.0.6", 0)
	blocked := connectionsAt(t, "127.0.0.5", port)
	fake := fakeIPFor(t, "rotating.test")
	lookups.Store(0)
	if !directFlowReaches(t, direct, &net.TCPAddr{IP: fake, Port: port}) {
		t.Error("the flow was not dialed at the address that passed the blocks")
	}
	if n := blocked.Load(); n != 0 {
		t.Errorf("the blocked address took %d connections", n)
	}
	if n := lookups.Load(); n != 1 {
		t.Errorf("the name was looked up %d times, want once", n)
	}
}

// An address the second record type answers late is not left out of the
// check by the wait the first one allowed: with nothing listening at the
// address that was checked, the flow does not fall through to one that was
// not.
func TestMihomoBridge_ProcessDirectTCPFlowNeverDialsAnAddressItDidNotCheck(t *testing.T) {
	skipWhereMihomoRaces(t)
	server := scriptedResolver(t, net.IPv4(127, 0, 0, 1), func(name string, qtype uint16) ([]D.RR, time.Duration) {
		header := D.RR_Header{Name: name + ".", Class: D.ClassINET, Ttl: 0}
		switch {
		case name != "late-v6.test":
			return nil, 0
		case qtype == D.TypeA:
			header.Rrtype = D.TypeA
			return []D.RR{&D.A{Hdr: header, A: net.IPv4(127, 0, 0, 6).To4()}}, 0
		case qtype == D.TypeAAAA:
			header.Rrtype = D.TypeAAAA
			return []D.RR{&D.AAAA{Hdr: header, AAAA: net.IPv6loopback}}, 400 * time.Millisecond
		}
		return nil, 0
	})
	prof := routing.Profile{
		Mode:  routing.ModeProxyAll,
		Tiers: []routing.Tier{{Block: []string{"::1/128"}, Direct: []string{"process:app.exe"}}},
	}
	_, _, direct := startMihomoBridgeThrough(t, &CoreController{}, prof, dnsconfig.Config{Servers: []string{server}}, socksRelay(t))
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	blocked := connectionsAt(t, "::1", port)
	fake := fakeIPFor(t, "late-v6.test")
	directFlowReaches(t, direct, &net.TCPAddr{IP: fake, Port: port})
	if n := blocked.Load(); n != 0 {
		t.Errorf("the blocked address took %d connections", n)
	}
}
