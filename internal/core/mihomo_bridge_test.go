//go:build !no_mihomo && (!no_xray || !no_awg)

package core

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	mihomoLog "github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
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
	mihomoTestHome(t)
	dns := dnsconfig.Config{}
	in, b := mihomoBridgeInbound(&dns, bridgeTestProfile)
	if !b.hijackDNS || !b.forceProxy {
		t.Fatalf("bridge plan %+v, want fake-ip DNS and a force-proxy dialer", b)
	}
	cfg, err := mihomoconfig.BuildConfig([]string{bridgeTestVlessLink}, in, mihomoconfig.Options{}, bridgeTestProfile)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	executor.ApplyConfig(cfg, true)
	t.Cleanup(mihomoTeardown)
	return mihomoBridgeProxies(x, b, x.sessionGen.Load())
}

func TestMihomoBridge_CarriesTCPAndUDP(t *testing.T) {
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
