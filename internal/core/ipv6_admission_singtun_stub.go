//go:build !with_gvisor || (no_mihomo && (no_xray || with_tun2socks))

package core

import "net/netip"

func setSingTunAdmission(func(netip.AddrPort) tcpVerdict) {}
