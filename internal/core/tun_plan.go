//go:build !no_xray && with_tun2socks

package core

import (
	"net/netip"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// tunPlan is what the Windows TUN gets before traffic flows: computed here,
// away from the Windows calls, so a session's profile can be checked against
// it without an adapter.
type tunPlan struct {
	// Addresses the TUN takes: the IPv4 one always, the IPv6 one with IPv6 on.
	Addresses []netip.Prefix
	// TunRoutes are the two halves of each family's default, on-link on the
	// TUN. They beat the physical adapter's /0 by prefix length without
	// touching it. With IPv6 off the v6 halves still enter the TUN: there the
	// engine's ::/0 reject rule drops them, while a route left on the physical
	// adapter would carry them out in the clear.
	TunRoutes []netip.Prefix
	// BypassRoutes go round the TUN through the physical gateway: the
	// routing.LocalNetworkTunBypass ranges, only when the profile keeps local networks
	// direct.
	BypassRoutes []netip.Prefix
	// InterfaceMetric is the lowest, so Windows asks the TUN's resolvers before
	// the physical adapter's.
	InterfaceMetric uint32
}

const (
	defaultTunCIDR   = "198.18.0.1/32"
	defaultTunCIDRv6 = "fdfe:dcba:9876::1/128"
)

var (
	tunHalvesV4 = []string{"0.0.0.0/1", "128.0.0.0/1"}
	tunHalvesV6 = []string{"::/1", "8000::/1"}
)

func planTun(ipv6, localNetworks bool) tunPlan {
	plan := tunPlan{
		Addresses:       []netip.Prefix{netip.MustParsePrefix(defaultTunCIDR)},
		InterfaceMetric: 1,
	}
	if ipv6 {
		plan.Addresses = append(plan.Addresses, netip.MustParsePrefix(defaultTunCIDRv6))
	}
	for _, cidr := range tunHalvesV4 {
		plan.TunRoutes = append(plan.TunRoutes, netip.MustParsePrefix(cidr))
	}
	for _, cidr := range tunHalvesV6 {
		plan.TunRoutes = append(plan.TunRoutes, netip.MustParsePrefix(cidr))
	}
	if localNetworks {
		for _, cidr := range routing.LocalNetworkTunBypass {
			plan.BypassRoutes = append(plan.BypassRoutes, netip.MustParsePrefix(cidr))
		}
	}
	return plan
}

// onLinkNextHop is the family's unspecified address: on a /32 or /128 TUN there
// is no neighbour to point a route at, and Windows reads 0.0.0.0 and :: as on-link.
func onLinkNextHop(destination netip.Prefix) netip.Addr {
	if destination.Addr().Is6() {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}
