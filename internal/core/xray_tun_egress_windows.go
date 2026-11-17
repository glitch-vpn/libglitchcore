//go:build !no_xray && !with_tun2socks && windows

package core

import (
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
	"github.com/metacubex/sing/common/logger"
)

// xrayDirectEgress is the physical NIC's name and IPv4: xray's direct egress
// binds them, else a direct flow loops back into the TUN (a source-IP bind
// alone does not keep it out). It is read before the adapter exists, from
// the route sing-tun's own interface monitor would pick as the default.
func xrayDirectEgress() (iface, sendThrough string) {
	updates, err := tun.NewNetworkUpdateMonitor(logger.NOP())
	if err != nil {
		return "", ""
	}
	monitor, err := tun.NewDefaultInterfaceMonitor(updates, logger.NOP(), tun.DefaultInterfaceMonitorOptions{InterfaceFinder: control.NewDefaultInterfaceFinder()})
	if err != nil {
		return "", ""
	}
	if err := monitor.Start(); err != nil {
		return "", ""
	}
	defer monitor.Close()
	physical := monitor.DefaultInterface()
	if physical == nil {
		return "", ""
	}
	for _, address := range physical.Addresses {
		if address.Addr().Is4() {
			return physical.Name, address.Addr().String()
		}
	}
	return physical.Name, ""
}
