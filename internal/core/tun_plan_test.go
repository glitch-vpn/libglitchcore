//go:build !no_xray && with_tun2socks

package core

import (
	"net/netip"
	"slices"
	"testing"
)

func prefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		out = append(out, netip.MustParsePrefix(cidr))
	}
	return out
}

func TestPlanTun_IPv6OnCarriesBothFamilies(t *testing.T) {
	plan := planTun(true, false)
	if !slices.Equal(plan.Addresses, prefixes("198.18.0.1/32", "fdfe:dcba:9876::1/128")) {
		t.Errorf("addresses: %v", plan.Addresses)
	}
	if !slices.Equal(plan.TunRoutes, prefixes("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1")) {
		t.Errorf("tun routes: %v", plan.TunRoutes)
	}
}

func TestPlanTun_IPv6OffRoutesV6IntoTunWithoutAddress(t *testing.T) {
	plan := planTun(false, false)
	if !slices.Equal(plan.Addresses, prefixes("198.18.0.1/32")) {
		t.Errorf("addresses: %v", plan.Addresses)
	}
	if !slices.Equal(plan.TunRoutes, prefixes("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1")) {
		t.Errorf("tun routes: %v", plan.TunRoutes)
	}
}

func TestPlanTun_LocalNetworksOnBypassesPrivateRangesOnly(t *testing.T) {
	plan := planTun(true, true)
	if !slices.Equal(plan.BypassRoutes, prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")) {
		t.Errorf("bypass routes: %v", plan.BypassRoutes)
	}
	for _, route := range plan.BypassRoutes {
		if route.Overlaps(netip.MustParsePrefix("100.64.0.0/10")) {
			t.Errorf("carrier-grade NAT range bypasses the TUN: %v", route)
		}
	}
}

func TestPlanTun_LocalNetworksOffBypassesNothing(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		if plan := planTun(ipv6, false); len(plan.BypassRoutes) != 0 {
			t.Errorf("ipv6=%v: bypass routes: %v", ipv6, plan.BypassRoutes)
		}
	}
}

func TestPlanTun_TunTakesTheLowestInterfaceMetric(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, local := range []bool{false, true} {
			if plan := planTun(ipv6, local); plan.InterfaceMetric != 1 {
				t.Errorf("ipv6=%v local=%v: metric %d", ipv6, local, plan.InterfaceMetric)
			}
		}
	}
}

func TestOnLinkNextHop_IsTheFamilysUnspecifiedAddress(t *testing.T) {
	if got := onLinkNextHop(netip.MustParsePrefix("0.0.0.0/1")); got != netip.IPv4Unspecified() {
		t.Errorf("v4: %v", got)
	}
	if got := onLinkNextHop(netip.MustParsePrefix("::/1")); got != netip.IPv6Unspecified() {
		t.Errorf("v6: %v", got)
	}
}
