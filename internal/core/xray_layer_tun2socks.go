//go:build !no_xray && with_tun2socks

package core

import (
	"sync/atomic"

	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
)

// startXrayTunLayer puts the tun2socks bridge in front of the instance: one
// bridge proxy per inbound tag a flow can enter by.
func (x *CoreController) startXrayTunLayer(p xrayTunParams) error {
	newProxy := func(tag string) (t2sproxy.Proxy, error) {
		in, err := newXrayInbound(p.instance, tag, p.sniffing)
		if err != nil {
			return nil, err
		}
		return x.newXrayBridgeProxy(in, p.mark), nil
	}
	appProxy, err := newProxy(xrayconfig.AppTrafficTag)
	if err != nil {
		return err
	}
	var forceProxy, forceDirect t2sproxy.Proxy
	if routingHasForceProxy(p.routing) {
		if forceProxy, err = newProxy(xrayconfig.ForceProxyTag); err != nil {
			return err
		}
	}
	if routingHasForceDirect(p.routing) {
		if forceDirect, err = newProxy(xrayconfig.ForceDirectTag); err != nil {
			return err
		}
	}
	return x.startTun2socks(tun2socksParams{
		proxy:       appProxy,
		forceProxy:  forceProxy,
		forceDirect: forceDirect,
		tunFd:       p.tunFd,
		serverIPv4s: p.serverHosts,
		dnsServer:   p.dnsServer,
		// Master switch off (default) holds tun2socks silent, whatever the connect logLevel.
		logLevel: xrayconfig.Tun2socksLogLevel(p.logLevel, atomic.LoadInt32(&statusVerbosity) >= 0),
		routing:  p.routing,
	})
}

func (x *CoreController) stopXrayTunLayer() { x.stopTun2socks() }

// xrayDirectEgress is the physical NIC's name and IPv4 on Windows, where
// direct egress must bind them or loop back into the TUN.
func xrayDirectEgress() (iface, sendThrough string) {
	return physicalInterfaceName(), physicalInterfaceIP()
}
