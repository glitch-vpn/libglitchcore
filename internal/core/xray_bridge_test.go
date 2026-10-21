//go:build !no_xray

package core

import (
	"context"
	"errors"
	"net"
	"testing"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	xrayCore "github.com/xtls/xray-core/core"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
)

// The TUN path's config: no inbound, the app's traffic routed by tag.
func startXrayForBridge(t *testing.T, prof routing.Profile, dns dnsconfig.Config) *xrayCore.Instance {
	t.Helper()
	res, err := xrayconfig.BuildConfig([]string{bridgeTestVlessLink}, xrayconfig.BalancerOptions{}, prof, "none")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	xrayconfig.ApplyDNS(res.Config, dns, prof)
	built, err := res.Config.Build()
	if err != nil {
		t.Fatalf("cfg.Build: %v", err)
	}
	inst, err := xrayCore.New(built)
	if err != nil {
		t.Fatalf("xray New: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("xray Start: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return inst
}

func xrayAppProxy(t *testing.T, x *CoreController, inst *xrayCore.Instance) *xrayBridgeProxy {
	t.Helper()
	p, err := x.newXrayBridgeProxy(inst, xrayconfig.AppTrafficTag, xrayconfig.AppSniffing(true), x.sessionGen.Load())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestXrayBridge_CarriesTCPAndUDP(t *testing.T) {
	inst := startXrayForBridge(t, routing.Profile{Mode: routing.ModeDirectAll}, dnsconfig.Config{Servers: []string{"1.1.1.1"}})
	p := xrayAppProxy(t, &CoreController{}, inst)
	requireTCPRoundTrip(t, p, tcpEcho(t), "ping")

	echo := udpEcho(t)
	pc, err := p.DialUDP(bridgeTestFlow(M.UDP, echo))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer pc.Close()
	requireUDPRoundTrip(t, pc, echo, make([]byte, 1400))
	requireNoThirdPartyReply(t, p)
}

// fake-ip: the app's :53 meets xray's DNS outbound through the app tag's rule.
func TestXrayBridge_AnswersTheAppsDNSWithFakeIPs(t *testing.T) {
	inst := startXrayForBridge(t, routing.Profile{}, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}})
	p := xrayAppProxy(t, &CoreController{}, inst)
	resolver := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
	pc, err := p.DialUDP(bridgeTestFlow(M.UDP, resolver))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer pc.Close()
	requireFakeIPAnswer(t, pc, resolver, "198.19.")
}

func TestXrayBridge_RefusesAfterItsSessionEnds(t *testing.T) {
	inst := startXrayForBridge(t, routing.Profile{Mode: routing.ModeDirectAll}, dnsconfig.Config{Servers: []string{"1.1.1.1"}})
	x := &CoreController{}
	p := xrayAppProxy(t, x, inst)
	x.clearSessionState()
	if conn, err := p.DialContext(context.Background(), bridgeTestFlow(M.TCP, tcpEcho(t))); !errors.Is(err, errSessionEnded) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("tcp after the session ended: %v, want errSessionEnded", err)
	}
	if pc, err := p.DialUDP(bridgeTestFlow(M.UDP, udpEcho(t))); !errors.Is(err, errSessionEnded) {
		if pc != nil {
			_ = pc.Close()
		}
		t.Fatalf("udp after the session ended: %v, want errSessionEnded", err)
	}
}

// A dial armed after a stop raced the start still belongs to the start's
// session, so it refuses.
func TestXrayTunnelDial_RefusesOnceItsStartsSessionEnded(t *testing.T) {
	x := &CoreController{}
	mark := x.sessionGen.Load()
	x.clearSessionState()
	dial := x.xrayTunnelDial(nil, xrayconfig.ExitEchoTag, mark)
	if conn, err := dial(context.Background(), "tcp", "example.com:443"); err == nil {
		_ = conn.Close()
		t.Fatal("a dial from an ended session must not reach xray")
	}
}
