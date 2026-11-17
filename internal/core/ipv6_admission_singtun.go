//go:build with_gvisor && (!no_mihomo || (!no_xray && !with_tun2socks))

package core

import (
	"net/netip"

	tun "github.com/metacubex/sing-tun"
)

// setSingTunAdmission sets the check mihomo's native gVisor stack asks before
// it answers a SYN; nil removes it.
func setSingTunAdmission(admit func(netip.AddrPort) tcpVerdict) {
	if admit == nil {
		tun.SetTCPAdmission(nil)
		return
	}
	tun.SetTCPAdmission(func(destination netip.AddrPort) tun.TCPVerdict {
		switch admit(destination) {
		case tcpReset:
			return tun.TCPReset
		case tcpDrop:
			return tun.TCPDrop
		}
		return tun.TCPAdmit
	})
}
