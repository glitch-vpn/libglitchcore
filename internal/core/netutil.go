package core

import (
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// process:->proxy rules need a mode-independent always-tunnel dialer; lives
// here (not with xray) because the mihomo bridge checks it too.
func routingHasForceProxy(prof routing.Profile) bool {
	return routingHasProcessTarget(prof, routing.TargetProxy)
}

// process:->direct rules need a dialer whose flows meet the blocks before
// they go direct.
func routingHasForceDirect(prof routing.Profile) bool {
	return routingHasProcessTarget(prof, routing.TargetDirect)
}

func routingHasProcessTarget(prof routing.Profile, want string) bool {
	for _, t := range routing.ProcessRules(prof) {
		if t == want {
			return true
		}
	}
	return false
}

// plainDNSServers returns the schemeless (UDP) resolvers - the only form usable
// to bootstrap mihomo's system resolver.
func plainDNSServers(dns dnsconfig.Config) []string {
	var out []string
	for _, s := range dns.Servers {
		if s = strings.TrimSpace(s); s != "" && dnsconfig.Scheme(s) == "" {
			out = append(out, s)
		}
	}
	return out
}

func splitLinks(raw string) []string {
	return strings.Split(raw, "\n")
}

var linkLinePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

var errRawConfigInPool = errors.New("a raw [Interface] config cannot share a pool; send each config in it as an awg:// link")

// isInterfaceHeader reads a section header the way the INI parsers do, so
// "[ interface ]" counts as a config's start here too.
func isInterfaceHeader(line string) bool {
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") &&
		strings.EqualFold(strings.Trim(line, "[] \t"), "interface")
}

// splitEngineLinks splits one link per line. A raw INI AmneziaWG config
// ("[Interface]") is one unit and travels alone: inside a pool its lines
// cannot be told apart from its neighbours', and a guess would shift every
// server position the caller counts on.
func splitEngineLinks(raw string) ([]string, error) {
	lines := splitLinks(raw)
	interfaces := 0
	for _, l := range lines {
		if isInterfaceHeader(l) {
			interfaces++
		}
	}
	if interfaces > 0 {
		if interfaces > 1 {
			return nil, errRawConfigInPool
		}
		for _, l := range lines {
			if linkLinePattern.MatchString(strings.TrimSpace(l)) {
				return nil, errRawConfigInPool
			}
		}
		return []string{strings.TrimSpace(raw)}, nil
	}
	var out []string
	for _, l := range splitLinks(raw) {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

// parseDNSListToAddrs reads the IPv4 servers of a DNS list, the only ones the
// TUN takes; a hostname or an IPv6 address is left out.
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
