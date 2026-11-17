//go:build !no_xray && with_tun2socks

package core

import (
	"context"
	"net"
	"net/netip"
	"runtime"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

var _ t2sproxy.Proxy = (*processSplitProxy)(nil)

// The owning process is resolved by source port before the flow reaches the
// engine; unmatched flows fall through to base. A flow the rules send direct
// or through the VPN still goes to the engine, under an inbound of its own, so
// the blocks of every tier meet it first.
type processSplitProxy struct {
	base        t2sproxy.Proxy
	forceProxy  t2sproxy.Proxy // always tunnels (may be nil)
	forceDirect t2sproxy.Proxy // meets the blocks, then goes direct (may be nil)
	split       processSplit
}

func (p *processSplitProxy) decide(m *M.Metadata) string {
	if m == nil {
		return ""
	}
	return p.split.target(m.Network.String(), netip.AddrPortFrom(m.SrcIP, m.SrcPort))
}

// proxyFor uses the always-tunnel proxy when present, else base
// (correct in proxy-all, where base's catch-all already proxies).
func (p *processSplitProxy) proxyFor() t2sproxy.Proxy {
	if p.forceProxy != nil {
		return p.forceProxy
	}
	return p.base
}

func (p *processSplitProxy) DialContext(ctx context.Context, m *M.Metadata) (net.Conn, error) {
	switch p.decide(m) {
	case routing.TargetDirect:
		if p.forceDirect == nil {
			return nil, errNoForceDirect
		}
		return p.forceDirect.DialContext(ctx, m)
	case routing.TargetBlock:
		return nil, errProcessBlocked
	case routing.TargetProxy:
		return p.proxyFor().DialContext(ctx, m)
	default:
		return p.base.DialContext(ctx, m)
	}
}

func (p *processSplitProxy) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	switch p.decide(m) {
	case routing.TargetDirect:
		if p.forceDirect == nil {
			return nil, errNoForceDirect
		}
		return p.forceDirect.DialUDP(m)
	case routing.TargetBlock:
		return nil, errProcessBlocked
	case routing.TargetProxy:
		return p.proxyFor().DialUDP(m)
	default:
		return p.base.DialUDP(m)
	}
}

// sessionBridgeProxy adds the desktop per-process split in front of the
// engine; Android routes per app in VpnService instead.
func sessionBridgeProxy(p tun2socksParams) t2sproxy.Proxy {
	var rules map[string]string
	if runtime.GOOS != "android" {
		rules = routing.ProcessRules(p.routing)
	}
	if len(rules) == 0 {
		return p.proxy
	}
	return &processSplitProxy{
		base:        p.proxy,
		forceProxy:  p.forceProxy,
		forceDirect: p.forceDirect,
		split:       processSplit{rules: rules},
	}
}
