//go:build !no_xray || (!no_mihomo && !no_awg)

package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/procname"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

var _ t2sproxy.Proxy = (*processSplitProxy)(nil)

// The owning process is resolved by source port before the flow reaches the
// engine; unmatched flows fall through to base.
type processSplitProxy struct {
	base        t2sproxy.Proxy
	forceProxy  t2sproxy.Proxy // always tunnels (may be nil)
	rules       map[string]string
	directIface string
	logged      sync.Map
}

func (p *processSplitProxy) decide(m *M.Metadata) string {
	if m == nil || len(p.rules) == 0 {
		return ""
	}
	name, err := procname.FindProcessName(m.Network.String(), m.SrcIP, int(m.SrcPort))
	if err != nil || name == "" {
		if _, seen := p.logged.LoadOrStore("ERR", true); !seen {
			logfmt.Warnf("[bridge] process-split: FindProcessName(%s %s:%d) failed: %v - per-process won't match", m.Network.String(), m.SrcIP, m.SrcPort, err)
		}
		return ""
	}
	exe := strings.ToLower(filepath.Base(name))
	target := p.rules[exe]
	if _, seen := p.logged.LoadOrStore(exe+"|"+target, true); !seen {
		log.Printf("[bridge] process-split saw %s -> rule=%q (forceProxy=%v)", exe, target, p.forceProxy != nil)
	}
	return target
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
		d := net.Dialer{Control: interfaceDialControl(p.directIface)}
		return d.DialContext(ctx, m.Network.String(), m.DestinationAddress())
	case routing.TargetBlock:
		return nil, fmt.Errorf("process split: blocked %s", m.DestinationAddress())
	case routing.TargetProxy:
		return p.proxyFor().DialContext(ctx, m)
	default:
		return p.base.DialContext(ctx, m)
	}
}

func (p *processSplitProxy) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	switch p.decide(m) {
	case routing.TargetDirect:
		lc := net.ListenConfig{Control: interfaceDialControl(p.directIface)}
		return lc.ListenPacket(context.Background(), "udp", "")
	case routing.TargetBlock:
		return nil, fmt.Errorf("process split: blocked %s", m.DestinationAddress())
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
		rules:       rules,
		directIface: physicalInterfaceName(),
	}
}
