//go:build !no_xray

package core

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// namedProxy records the flows it is handed and refuses them.
type namedProxy struct{ dialed int }

func (p *namedProxy) DialContext(context.Context, *M.Metadata) (net.Conn, error) {
	p.dialed++
	return nil, net.ErrClosed
}

func (p *namedProxy) DialUDP(*M.Metadata) (net.PacketConn, error) {
	p.dialed++
	return nil, net.ErrClosed
}

var _ t2sproxy.Proxy = (*namedProxy)(nil)

// A flow of an app the rules send direct goes to the engine under the
// force-direct inbound, where the blocks meet it, and never to a socket of the
// dialer's own.
func TestProcessSplitProxy_DirectFlowsGoToTheEngineForTheBlocks(t *testing.T) {
	base, force, direct := &namedProxy{}, &namedProxy{}, &namedProxy{}
	split := &processSplitProxy{
		base:        base,
		forceProxy:  force,
		forceDirect: direct,
		rules:       map[string]string{"direct.exe": routing.TargetDirect, "proxy.exe": routing.TargetProxy},
		processName: func(*M.Metadata) (string, error) {
			return filepath.Join(string(filepath.Separator), "apps", "Direct.exe"), nil
		},
	}
	flow := bridgeTestFlow(M.TCP, &net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 443})
	_, _ = split.DialContext(context.Background(), flow)
	_, _ = split.DialUDP(bridgeTestFlow(M.UDP, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 443}))
	if direct.dialed != 2 || base.dialed != 0 || force.dialed != 0 {
		t.Fatalf("flows to force-direct %d, base %d, force-proxy %d; want 2, 0, 0", direct.dialed, base.dialed, force.dialed)
	}
}

func TestProcessSplitProxy_DirectFlowWithoutAForceDirectDialerIsRefused(t *testing.T) {
	base := &namedProxy{}
	split := &processSplitProxy{
		base:        base,
		rules:       map[string]string{"direct.exe": routing.TargetDirect},
		processName: func(*M.Metadata) (string, error) { return "direct.exe", nil },
	}
	flow := bridgeTestFlow(M.TCP, &net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 443})
	if _, err := split.DialContext(context.Background(), flow); err != errNoForceDirect {
		t.Fatalf("DialContext = %v, want errNoForceDirect", err)
	}
	if base.dialed != 0 {
		t.Fatal("the flow reached the engine's tiers")
	}
}
