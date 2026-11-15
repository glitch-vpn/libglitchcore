package xrayconfig

import (
	"net"

	xrayConf "github.com/xtls/xray-core/infra/conf"
)

// bindServerDial sends an outbound's own dial to its server through the
// physical adapter, like the direct outbound: on Windows the TUN holds both
// families' default routes, and a dial to a server no host route pinned (an
// IPv6 one) would otherwise enter the tunnel it carries. A loopback server
// is reached by no adapter and stays unbound; a hop after the first dials
// through the hop before it and never comes here.
func bindServerDial(ob *xrayConf.OutboundDetourConfig, serverHost, physicalInterface string) {
	if physicalInterface == "" || serverHost == "localhost" {
		return
	}
	if ip := net.ParseIP(serverHost); ip != nil && ip.IsLoopback() {
		return
	}
	if ob.StreamSetting == nil {
		ob.StreamSetting = &xrayConf.StreamConfig{}
	}
	if ob.StreamSetting.SocketSettings == nil {
		ob.StreamSetting.SocketSettings = &xrayConf.SocketConfig{}
	}
	ob.StreamSetting.SocketSettings.Interface = physicalInterface
}
