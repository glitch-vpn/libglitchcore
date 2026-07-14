// Package routing is the engine-neutral routing intent (proxy/direct/block matchers).
package routing

import (
	"net"
	"strings"
)

const (
	ModeProxyAll  = "proxy-all"  // default: unlisted traffic -> proxy
	ModeDirectAll = "direct-all" // unlisted traffic -> direct
)

const (
	TargetProxy  = "proxy"
	TargetDirect = "direct"
	TargetBlock  = "block"
)

// ProcessRules: process:NAME -> target. Mihomo uses PROCESS-NAME; xray applies
// direct/block in the tun2socks dialer (xray can't see the real app behind it).
// Priority block > direct > proxy (later writes win).
func ProcessRules(p Profile) map[string]string {
	out := map[string]string{}
	add := func(list []string, target string) {
		for _, m := range list {
			if kind, val, ok := Classify(m); ok && kind == KindProcess {
				out[strings.ToLower(strings.TrimSpace(val))] = target
			}
		}
	}
	add(p.Proxy, TargetProxy)
	add(p.Direct, TargetDirect)
	add(p.Block, TargetBlock)
	return out
}

// LocalNetworkCIDRs are routed direct so LAN/router/loopback stay reachable
// while the tunnel is up.
var LocalNetworkCIDRs = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
	"169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128",
}

// Profile priority: Block -> Direct/Proxy -> local networks -> Mode catch-all.
type Profile struct {
	Mode              string
	Proxy             []string
	Direct            []string
	Block             []string
	LocalNetworks     bool
	DirectSendThrough string // bind direct egress to this NIC IP (Windows, source IP)
	DirectInterface   string // bind direct egress to this NIC by name (Windows, IP_UNICAST_IF) - required so direct traffic escapes the TUN default route
	// DisableIPv6 blocks all IPv6 traffic (::/0 -> reject) ahead of every other
	// rule; the DNS side (AAAA suppression) is carried by dnsconfig.Config.
	DisableIPv6 bool
	// DisableUDP blocks UDP except :53 - DNS must survive so name resolution
	// (and fake-ip interception) keeps working.
	DisableUDP bool
}

func (p Profile) ResolvedMode() string {
	if p.Mode == ModeDirectAll {
		return ModeDirectAll
	}
	return ModeProxyAll
}

type MatchKind int

const (
	KindDomainSuffix  MatchKind = iota // domain + subdomains (also the bare default)
	KindDomainFull                     // exact domain
	KindDomainKeyword                  // substring keyword
	KindDomainRegex
	KindGeoSite // geosite category (from geosite.dat)
	KindGeoIP   // geoip country/category (from geoip.dat)
	KindIPCIDR
	KindProcess // desktop process name
)

// Classify: IP/CIDR first (IPv6 colons ≠ prefix), then known prefixes, else domain suffix.
func Classify(entry string) (kind MatchKind, value string, ok bool) {
	e := strings.TrimSpace(entry)
	if e == "" {
		return 0, "", false
	}
	if isIPOrCIDR(e) {
		return KindIPCIDR, e, true
	}
	if i := strings.IndexByte(e, ':'); i > 0 {
		val := strings.TrimSpace(e[i+1:])
		if val == "" {
			return 0, "", false
		}
		switch strings.ToLower(e[:i]) {
		case "geoip":
			return KindGeoIP, strings.ToLower(val), true
		case "geosite":
			return KindGeoSite, strings.ToLower(val), true
		case "domain":
			return KindDomainSuffix, val, true
		case "full":
			return KindDomainFull, val, true
		case "keyword":
			return KindDomainKeyword, val, true
		case "regexp", "regex":
			return KindDomainRegex, val, true
		case "process":
			return KindProcess, val, true
		}
	}
	return KindDomainSuffix, e, true
}

func isIPOrCIDR(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// ValidGeoCode: ASCII letters/digits/hyphen/underscore only - non-ASCII would fail the whole config.
func ValidGeoCode(code string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	for _, r := range code {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func NormalizeCIDR(ipOrCIDR string) string {
	s := strings.TrimSpace(ipOrCIDR)
	if strings.Contains(s, "/") {
		return s
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return s + "/32"
		}
		return s + "/128"
	}
	return s
}
