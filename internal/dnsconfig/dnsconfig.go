// Package dnsconfig is the engine-neutral DNS intent (mode, servers, fake-ip filter).
package dnsconfig

import (
	"net"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

const (
	ModeFakeIP = "fake-ip"
	ModeNormal = "normal"
)

type Config struct {
	Mode         string   `json:"mode"` // "fake-ip" | "normal" (default)
	Servers      []string `json:"servers"`
	FakeIPFilter []string `json:"fakeIpFilter"` // domains kept off fake-ip (direct-resolved)
	// Static name -> addresses entries. Keys: bare hostname (exact match) or
	// engine-native matcher syntax passed through verbatim (xray:
	// domain:/geosite:/regexp:/keyword: prefixes). awg ignores.
	Hosts map[string][]string `json:"hosts,omitempty"`
	// Resolvers for direct-routed names. mihomo maps them to
	// direct-nameserver; xray has no such switch, so they are placed behind
	// fakedns, where the module's own lookups land - the ones freedom makes
	// when it dials a direct-routed name. Normal (non-fake-ip) mode has no
	// fakedns to fall through, so there they are scoped by the profile's
	// direct domain rules instead (direct-all: they become the default and the
	// general list is scoped to the proxy rules). awg ignores.
	DirectServers []string `json:"directServers,omitempty"`
	// From opts["disableIPv6"], not dnsConfig JSON; routing side is Profile.DisableIPv6.
	DisableIPv6 bool `json:"-"`
}

func (c Config) FakeIP() bool { return strings.EqualFold(strings.TrimSpace(c.Mode), ModeFakeIP) }

func trimmed(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (c Config) NormalizedServers(fallback string) []string {
	out := trimmed(c.Servers)
	if len(out) == 0 {
		if f := strings.TrimSpace(fallback); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (c Config) NormalizedFilter() []string { return trimmed(c.FakeIPFilter) }

func (c Config) NormalizedDirectServers() []string { return trimmed(c.DirectServers) }

// NormalizedHosts drops entries the engines cannot take, per entry: mihomo
// fails the whole config on one bad value and xray drops the whole table, so
// a single typo must not cost the caller every other mapping. A multi-value
// entry keeps only IPs (an alias target is single-valued by definition); a
// single value may be an IP or another name.
func (c Config) NormalizedHosts() map[string][]string {
	out := map[string][]string{}
	for k, vals := range c.Hosts {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		clean := trimmed(vals)
		if len(clean) > 1 {
			ips := clean[:0]
			for _, v := range clean {
				if net.ParseIP(v) != nil {
					ips = append(ips, v)
				} else {
					logfmt.Warnf("[DNS] hosts %q: dropping non-IP %q from a multi-value entry", k, v)
				}
			}
			clean = ips
		} else if len(clean) == 1 && net.ParseIP(clean[0]) == nil && !isHostName(clean[0]) {
			logfmt.Warnf("[DNS] hosts %q: dropping unusable value %q", k, clean[0])
			clean = nil
		}
		if len(clean) > 0 {
			out[k] = clean
		}
	}
	return out
}

// isHostName: an alias target, i.e. a name the resolver can look up again.
func isHostName(v string) bool {
	if v == "" || strings.ContainsAny(v, " \t/\\:,") {
		return false
	}
	return strings.Contains(v, ".") || strings.EqualFold(v, "lan")
}

// FirstPlainServer skips DoH/DoT/DoQ - AWG only accepts a plain UDP resolver on the interface.
func (c Config) FirstPlainServer() string {
	for _, s := range c.Servers {
		if s = strings.TrimSpace(s); s != "" && Scheme(s) == "" {
			return s
		}
	}
	return ""
}

func Scheme(server string) string {
	server = strings.TrimSpace(server)
	if i := strings.Index(server, "://"); i > 0 {
		return strings.ToLower(server[:i])
	}
	return ""
}
