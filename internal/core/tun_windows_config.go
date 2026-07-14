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
)

const (
	defaultTunCIDR = "198.18.0.1/32"
	logPrefix      = "[WINDOWS][TUNCONFIG]"
)

var (
	familyUnspec = winipcfg.AddressFamily(windows.AF_UNSPEC)
	familyIPv4   = winipcfg.AddressFamily(windows.AF_INET)
)

// State that cleanupTun must reverse (assigned addresses, pinned routes, excludes).
var (
	lastPhyLUID       winipcfg.LUID
	lastServerIPv4s   []netip.Addr
	lastExclusionsSet bool
	lastPhyIfIndex    uint32
)

func setAddressWithRetry(luid winipcfg.LUID, pfx netip.Prefix) bool {
	for i := 0; i < 20; i++ {
		if err := luid.SetIPAddressesForFamily(familyIPv4, []netip.Prefix{pfx}); err == nil {
			return true
		} else if err == windows.ERROR_NOT_FOUND {
			time.Sleep(400 * time.Millisecond)
			continue
		} else {
			log.Printf("%s SetIPAddressesForFamily: %v", logPrefix, err)
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

func findInterfaceByIPv4Addr(ipv4 string) (winipcfg.LUID, uint32, bool) {
	target := net.ParseIP(ipv4)
	if target == nil || target.To4() == nil {
		return 0, 0, false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, 0, false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.To4() != nil && ip.Equal(target) {
				luid, e := winipcfg.LUIDFromIndex(uint32(iface.Index))
				if e != nil {
					return 0, 0, false
				}
				return luid, uint32(iface.Index), true
			}
		}
	}
	return 0, 0, false
}

func parseDNSListToAddrs(s string) []netip.Addr {
	s = strings.TrimSpace(strings.NewReplacer(",", " ", ";", " ", "\t", " ").Replace(s))
	var out []netip.Addr
	seen := map[string]struct{}{}
	for _, tok := range strings.Fields(s) {
		h := tok
		if hh, _, err := net.SplitHostPort(tok); err == nil && hh != "" {
			h = hh
		}
		ip, err := netip.ParseAddr(h)
		if err != nil || !ip.Is4() {
			continue
		}
		if _, ok := seen[ip.String()]; ok {
			continue
		}
		seen[ip.String()] = struct{}{}
		out = append(out, ip)
	}
	return out
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
		log.Printf("%s: cannot get LUID from tun ifIndex=%d: %v", logPrefix, tunIfIndex, err)
		return
	}
	servers := parseDNSListToAddrs(dnsAddr)
	if len(servers) == 0 {
		log.Printf("%s: no valid IPv4 DNS in %q; TUN DNS unchanged", logPrefix, dnsAddr)
		return
	}
	if err := setDnsServersForLuid(luidTun, servers); err != nil {
		log.Printf("%s: SetDNS(TUN if=%d) failed: %v", logPrefix, tunIfIndex, err)
	} else {
		log.Printf("%s: SetDNS(TUN if=%d) = %v", logPrefix, tunIfIndex, servers)
	}
}

func configureTunV3(ifaceName, tunCIDR string, serverHostsOrIPv4 []string, dnsAddr string) error {
	if tunCIDR == "" {
		tunCIDR = defaultTunCIDR
	}

	tunPfx, err := netip.ParsePrefix(strings.TrimSpace(tunCIDR))
	if err != nil {
		return fmt.Errorf("%s: bad tunCIDR %q: %v", logPrefix, tunCIDR, err)
	}

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
		if assigned = setAddressWithRetry(luidTun, tunPfx); !assigned {
			log.Printf("%s: failed to assign %s to LUID=%v (retry %d/%d)", logPrefix, tunPfx, luidTun, i+1, 50)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		break
	}
	if !ok || !assigned {
		return fmt.Errorf("%s: cannot setup TUN address on iface like %q", logPrefix, ifaceName)
	}

	// For a /32 TUN use an on-link next hop (0.0.0.0); else the interface address.
	var nextHop netip.Addr
	if tunPfx.Bits() == 32 {
		nextHop = netip.MustParseAddr("0.0.0.0")
	} else {
		nextHop = tunPfx.Addr()
	}
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		pfx := netip.MustParsePrefix(cidr)
		if err := luidTun.AddRoute(pfx, nextHop, 1); err != nil {
			l := strings.ToLower(err.Error())
			if !strings.Contains(l, "exists") {
				log.Printf("%s route: add %s via %s failed: %v", logPrefix, cidr, nextHop, err)
			}
		}
	}

	// Exclude LAN/CGN ranges via the physical gateway so they bypass the TUN.
	if gw, ifIdx, gwErr := defaultGateway(); gwErr == nil {
		if phyLuid, luidErr := winipcfg.LUIDFromIndex(ifIdx); luidErr == nil {
			for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"} {
				pfx := netip.MustParsePrefix(cidr)
				if err := phyLuid.AddRoute(pfx, gw, 1); err != nil {
					if !strings.Contains(strings.ToLower(err.Error()), "exists") {
						log.Printf("%s route: add exclude %s via %s(if=%d) failed: %v", logPrefix, cidr, gw, ifIdx, err)
					}
				}
			}
			lastPhyLUID = phyLuid
			lastPhyIfIndex = ifIdx
			lastExclusionsSet = true
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
				log.Printf("%s server pre-resolve FAILED for %q: %v", logPrefix, serverHostOrIPv4, rerr)
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
		_ = luidTun.DeleteRoute(host, netip.MustParseAddr("0.0.0.0"))
		if phyLuid2, luidErr := winipcfg.LUIDFromIndex(gwIfIdx); luidErr == nil {
			if err := phyLuid2.AddRoute(host, gw, 1); err != nil {
				e := strings.ToLower(err.Error())
				if strings.Contains(e, "exists") {
					log.Printf("%s: host route already exists %s via %s(if=%d)", logPrefix, host, gw, gwIfIdx)
				} else {
					log.Printf("%s route: add host %s via %s(if=%d) failed: %v", logPrefix, host, gw, gwIfIdx, err)
				}
			}
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

	// Delete split defaults with both next-hop variants: on-link (0.0.0.0) for
	// /32 setups, via 198.18.0.1 for the xray case.
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		pfx := netip.MustParsePrefix(cidr)
		_ = luidTun.DeleteRoute(pfx, netip.MustParseAddr("0.0.0.0"))
		_ = luidTun.DeleteRoute(pfx, netip.MustParseAddr("198.18.0.1"))
	}

	_ = luidTun.FlushIPAddresses(familyIPv4)
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

	if lastExclusionsSet && lastPhyLUID != 0 {
		if gw, _, err := defaultGateway(); err == nil {
			for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"} {
				_ = lastPhyLUID.DeleteRoute(netip.MustParsePrefix(cidr), gw)
			}
		}
		lastExclusionsSet = false
		lastPhyLUID = 0
		lastPhyIfIndex = 0
	}
}
