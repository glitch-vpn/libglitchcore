//go:build no_mihomo || !with_gvisor

package core

import "net/netip"

func setSingTunAdmission(func(netip.AddrPort) tcpVerdict) {}
