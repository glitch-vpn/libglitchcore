//go:build windows

package core

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

const logPrefix = "[WINDOWS][TUNCONFIG]"

var (
	familyUnspec = winipcfg.AddressFamily(windows.AF_UNSPEC)
	familyIPv4   = winipcfg.AddressFamily(windows.AF_INET)
	familyIPv6   = winipcfg.AddressFamily(windows.AF_INET6)
)

var (
	lastPlan        tunPlan
	lastPhyLUID     winipcfg.LUID
	lastServerIPv4s []netip.Addr
)

func addressFamily(prefix netip.Prefix) winipcfg.AddressFamily {
	if prefix.Addr().Is6() {
		return familyIPv6
	}
	return familyIPv4
}

func setAddressWithRetry(luid winipcfg.LUID, pfx netip.Prefix) bool {
	for i := 0; i < 20; i++ {
		if err := luid.SetIPAddressesForFamily(addressFamily(pfx), []netip.Prefix{pfx}); err == nil {
			return true
		} else if err == windows.ERROR_NOT_FOUND {
			time.Sleep(400 * time.Millisecond)
			continue
		} else {
			logfmt.Errorf("%s SetIPAddressesForFamily(%s): %v", logPrefix, pfx, err)
			return false
		}
	}
	return false
}

func waitForInterfaceLike(name string) (winipcfg.LUID, bool) {
	for i := 0; i < 50; i++ {
		ifs, _ := winipcfg.GetAdaptersAddresses(familyUnspec, winipcfg.GAAFlagIncludeAll)
		var candidateLUID winipcfg.LUID
		var found bool
		var bestIdx uint32
		for _, ad := range ifs {
			fn := ad.FriendlyName()
			if friendlyMatch(fn, name) {
				if !found || ad.IfIndex > bestIdx {
					bestIdx = ad.IfIndex
					candidateLUID = ad.LUID
					found = true
				}
			}
		}
		if found {
			return candidateLUID, true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0, false
}

func friendlyMatch(actual, expected string) bool {
	if actual == expected {
		return true
	}
	if strings.HasPrefix(actual, expected) {
		rest := strings.TrimSpace(strings.TrimPrefix(actual, expected))
		if rest == "" {
			return true
		}
		for _, r := range rest {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	return false
}

func setDnsServersForLuid(luid winipcfg.LUID, servers []netip.Addr) error {
	return luid.SetDNS(familyIPv4, servers, nil)
}

func luidToIfIndex(luid winipcfg.LUID) (uint32, bool) {
	ifs, err := winipcfg.GetAdaptersAddresses(familyUnspec, winipcfg.GAAFlagIncludeAll)
	if err != nil {
		return 0, false
	}
	for _, ad := range ifs {
		if ad.LUID == luid {
			return ad.IfIndex, true
		}
	}
	return 0, false
}

func defaultGateway() (gw netip.Addr, ifIdx uint32, err error) {
	tbl, err := winipcfg.GetIPForwardTable2(familyIPv4)
	if err != nil {
		return
	}
	best := uint32(^uint32(0))
	for _, r := range tbl {
		if r.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		hop := r.NextHop.Addr()
		if !hop.Is4() {
			continue
		}
		if r.Metric < best {
			best = r.Metric
			gw = hop
			ifIdx = r.InterfaceIndex
		}
	}
	if !gw.IsValid() {
		err = fmt.Errorf("no default gateway")
	}
	return
}

// providerLookupIPv4 resolves host via the system resolver -- it runs BEFORE TUN
// routes exist, so it must not depend on them.
func providerLookupIPv4(ctx context.Context, host string) (string, error) {
	rctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(rctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("providerLookupIPv4: resolve %s failed: %w", host, err)
	}
	return ips[0].String(), nil
}

func setDNS(tunIfIndex uint32, dnsAddr string) {
	luidTun, err := winipcfg.LUIDFromIndex(tunIfIndex)
	if err != nil {
		logfmt.Errorf("%s: cannot get LUID from tun ifIndex=%d: %v", logPrefix, tunIfIndex, err)
		return
	}
	servers := parseDNSListToAddrs(dnsAddr)
	if len(servers) == 0 {
		logfmt.Warnf("%s: no valid IPv4 DNS in %q; TUN DNS unchanged", logPrefix, dnsAddr)
		return
	}
	if err := setDnsServersForLuid(luidTun, servers); err != nil {
		logfmt.Errorf("%s: SetDNS(TUN if=%d) failed: %v", logPrefix, tunIfIndex, err)
	} else {
		log.Printf("%s: SetDNS(TUN if=%d) = %v", logPrefix, tunIfIndex, servers)
	}
}

// setInterfaceMetric pins one family's interface metric; automatic is the
// way back on cleanup.
func setInterfaceMetric(luid winipcfg.LUID, family winipcfg.AddressFamily, metric uint32, automatic bool) {
	row, err := luid.IPInterface(family)
	if err != nil {
		logfmt.Errorf("%s: IPInterface(family=%d): %v", logPrefix, family, err)
		return
	}
	row.UseAutomaticMetric = automatic
	row.Metric = metric
	if err := row.Set(); err != nil {
		logfmt.Errorf("%s: set interface metric (family=%d, metric=%d, automatic=%v): %v", logPrefix, family, metric, automatic, err)
	}
}

func addRouteIgnoringExisting(luid winipcfg.LUID, destination netip.Prefix, nextHop netip.Addr, what string) {
	if err := luid.AddRoute(destination, nextHop, 1); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "exists") {
			logfmt.Errorf("%s route: add %s %s via %s failed: %v", logPrefix, what, destination, nextHop, err)
		}
	}
}

func configureTunV3(ifaceName string, serverHostsOrIPv4 []string, dnsAddr string, plan tunPlan) error {
	var (
		luidTun  winipcfg.LUID
		ok       bool
		assigned bool
	)
	for i := 0; i < 50; i++ {
		luidTun, ok = waitForInterfaceLike(ifaceName)
		if !ok {
			log.Printf("%s: interface like %q not present yet (%d/50)", logPrefix, ifaceName, i+1)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		assigned = true
		for _, address := range plan.Addresses {
			if assigned = setAddressWithRetry(luidTun, address); !assigned {
				logfmt.Warnf("%s: failed to assign %s to LUID=%v (retry %d/%d)", logPrefix, address, luidTun, i+1, 50)
				break
			}
		}
		if !assigned {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		break
	}
	if !ok || !assigned {
		return fmt.Errorf("%s: cannot setup TUN address on iface like %q", logPrefix, ifaceName)
	}
	lastPlan = plan

	for _, route := range plan.TunRoutes {
		addRouteIgnoringExisting(luidTun, route, onLinkNextHop(route), "tun")
	}
	setInterfaceMetric(luidTun, familyIPv4, plan.InterfaceMetric, false)
	setInterfaceMetric(luidTun, familyIPv6, plan.InterfaceMetric, false)

	if len(plan.BypassRoutes) > 0 {
		if gw, ifIdx, gwErr := defaultGateway(); gwErr == nil {
			if phyLuid, luidErr := winipcfg.LUIDFromIndex(ifIdx); luidErr == nil {
				for _, route := range plan.BypassRoutes {
					addRouteIgnoringExisting(phyLuid, route, gw, "bypass")
				}
				lastPhyLUID = phyLuid
			}
		}
	}

	// Pre-resolve each server to IPv4 and pin a /32 via the physical NIC so
	// proxy-server traffic bypasses the TUN.
	lastServerIPv4s = nil
	var (
		gw              netip.Addr
		gwIfIdx         uint32
		gatewayResolved bool
	)
	for _, serverHostOrIPv4 := range serverHostsOrIPv4 {
		if serverHostOrIPv4 == "" {
			continue
		}
		var serverIPv4Addr netip.Addr
		if ip, e := netip.ParseAddr(serverHostOrIPv4); e == nil && ip.Is4() {
			serverIPv4Addr = ip
		} else {
			rctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			ipStr, rerr := providerLookupIPv4(rctx, serverHostOrIPv4)
			cancel()
			if rerr == nil && ipStr != "" {
				serverIPv4Addr = netip.MustParseAddr(ipStr)
				log.Printf("%s server pre-resolve (system): %s -> %s", logPrefix, serverHostOrIPv4, ipStr)
			} else {
				logfmt.Errorf("%s server pre-resolve FAILED for %q: %v", logPrefix, serverHostOrIPv4, rerr)
			}
		}
		if !serverIPv4Addr.IsValid() {
			continue
		}

		if !gatewayResolved {
			g, idx, gwErr := defaultGateway()
			if gwErr != nil {
				return fmt.Errorf("%s: failed to get default gateway: %v", logPrefix, gwErr)
			}
			gw, gwIfIdx, gatewayResolved = g, idx, true
		}

		host := netip.PrefixFrom(serverIPv4Addr, 32)
		// Remove any stale on-link route first (safe no-op).
		_ = luidTun.DeleteRoute(host, netip.IPv4Unspecified())
		if phyLuid2, luidErr := winipcfg.LUIDFromIndex(gwIfIdx); luidErr == nil {
			addRouteIgnoringExisting(phyLuid2, host, gw, "server")
			lastServerIPv4s = append(lastServerIPv4s, serverIPv4Addr)
		}
	}

	if ifIdx, ok := luidToIfIndex(luidTun); ok {
		setDNS(ifIdx, dnsAddr)
	} else {
		return fmt.Errorf("%s: cannot resolve ifIndex for TUN LUID", logPrefix)
	}

	return nil
}

// physicalInterfaceIP is the IPv4 of the default gateway's interface, used to
// bind Xray's "freedom" outbound so direct traffic bypasses the TUN.
func physicalInterfaceIP() string {
	_, ifIdx, err := defaultGateway()
	if err != nil {
		return ""
	}
	iface, err := net.InterfaceByIndex(int(ifIdx))
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

// physicalInterfaceName is the default gateway's interface name - set as xray's
// sockopt.interface (IP_UNICAST_IF), so direct traffic egresses the NIC instead
// of looping into the TUN (a source-IP bind via SendThrough is not enough).
func physicalInterfaceName() string {
	_, ifIdx, err := defaultGateway()
	if err != nil {
		return ""
	}
	iface, err := net.InterfaceByIndex(int(ifIdx))
	if err != nil {
		return ""
	}
	return iface.Name
}

func cleanupTun(ifaceName string) {
	log.Printf("%s: cleanupTun", logPrefix)

	luidTun, ok := waitForInterfaceLike(ifaceName)
	if !ok {
		log.Printf("%s: cleanupTun: TUN interface %q not found, skipping", logPrefix, ifaceName)
		return
	}

	for _, route := range lastPlan.TunRoutes {
		_ = luidTun.DeleteRoute(route, onLinkNextHop(route))
	}
	setInterfaceMetric(luidTun, familyIPv4, 0, true)
	setInterfaceMetric(luidTun, familyIPv6, 0, true)

	_ = luidTun.FlushIPAddresses(familyIPv4)
	_ = luidTun.FlushIPAddresses(familyIPv6)
	_ = luidTun.SetDNS(familyIPv4, nil, nil)

	if len(lastServerIPv4s) > 0 {
		if gw, ifIdx, err := defaultGateway(); err == nil {
			if phyLuid, e := winipcfg.LUIDFromIndex(ifIdx); e == nil {
				for _, ip := range lastServerIPv4s {
					_ = phyLuid.DeleteRoute(netip.PrefixFrom(ip, 32), gw)
				}
			}
		}
		lastServerIPv4s = nil
	}

	if len(lastPlan.BypassRoutes) > 0 && lastPhyLUID != 0 {
		if gw, _, err := defaultGateway(); err == nil {
			for _, route := range lastPlan.BypassRoutes {
				_ = lastPhyLUID.DeleteRoute(route, gw)
			}
		}
		lastPhyLUID = 0
	}
	lastPlan = tunPlan{}
}
