//go:build !no_xray || (!no_mihomo && !no_awg)

package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xjasonlyu/tun2socks/v2/proxy/reject"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"

	"github.com/glitch-vpn/libglitchcore/internal/procname"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

var _ t2sproxy.Proxy = (*processSplitProxy)(nil)

// The proxy's own `process` matcher is useless behind tun2socks (every flow
// looks like the bridge), so the owning process is resolved by source port
// before the SOCKS hop; unmatched flows fall through to base.
type processSplitProxy struct {
	base        t2sproxy.Proxy
	forceProxy  t2sproxy.Proxy // always-tunnel inbound (may be nil)
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
			log.Printf("[bridge] process-split: FindProcessName(%s %s:%d) failed: %v - per-process won't match", m.Network.String(), m.SrcIP, m.SrcPort, err)
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

// proxyFor uses the dedicated always-tunnel inbound when present, else base
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

// Desktop-only wrap of tun2socks with DNS redirect and/or per-process split.
func (x *CoreController) maybeInstallBridgeProxy(prof routing.Profile, forceProxyURL, dnsRedirectAddr string) {
	var rules map[string]string
	if runtime.GOOS != "android" {
		rules = routing.ProcessRules(prof)
	}
	if len(rules) == 0 && dnsRedirectAddr == "" {
		return
	}
	go installBridgeProxy(rules, forceProxyURL, dnsRedirectAddr)
}

// Wait for real SOCKS (not reject), then wrap SOCKS -> dnsRedirect -> processSplit
// so process->direct :53 is served before fake-ip redirect can rewrite it.
func installBridgeProxy(rules map[string]string, forceProxyURL, dnsRedirectAddr string) {
	var forceProxy t2sproxy.Proxy
	if forceProxyURL != "" {
		if u, err := url.Parse(forceProxyURL); err == nil {
			if fp, perr := t2sproxy.Parse(u); perr == nil {
				forceProxy = fp
			} else {
				log.Printf("[bridge] force-proxy parse: %v", perr)
			}
		}
	}
	for i := 0; i < 150; i++ {
		base := tunnel.T().Proxy()
		if base != nil && !isRejectProxy(base) && !isBridgeWrapper(base) {
			wrapped := base
			if dnsRedirectAddr != "" {
				wrapped = &dnsRedirectProxy{base: wrapped, dnsAddr: dnsRedirectAddr}
			}
			if len(rules) > 0 {
				wrapped = &processSplitProxy{
					base:        wrapped,
					forceProxy:  forceProxy,
					rules:       rules,
					directIface: physicalInterfaceName(),
				}
			}
			tunnel.T().SetProxy(wrapped)
			log.Printf("[bridge] proxy installed (process rules=%d, dnsRedirect=%v, forceProxy=%v)", len(rules), dnsRedirectAddr != "", forceProxy != nil)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	log.Printf("[bridge] base proxy not ready in time, skipped")
}

func isRejectProxy(p t2sproxy.Proxy) bool {
	_, ok := p.(*reject.Reject)
	return ok
}

func isBridgeWrapper(p t2sproxy.Proxy) bool {
	switch p.(type) {
	case *processSplitProxy, *dnsRedirectProxy:
		return true
	}
	return false
}
