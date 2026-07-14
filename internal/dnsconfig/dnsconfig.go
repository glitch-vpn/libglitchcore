// Package dnsconfig is the engine-neutral DNS intent (mode, servers, fake-ip filter).
package dnsconfig

import "strings"

const (
	ModeFakeIP = "fake-ip"
	ModeNormal = "normal"
)

type Config struct {
	Mode         string   `json:"mode"` // "fake-ip" | "normal" (default)
	Servers      []string `json:"servers"`
	FakeIPFilter []string `json:"fakeIpFilter"` // domains kept off fake-ip (direct-resolved)
	// From opts["disableIPv6"], not dnsConfig JSON; routing side is Profile.DisableIPv6.
	DisableIPv6 bool `json:"-"`
}

func (c Config) FakeIP() bool { return strings.EqualFold(strings.TrimSpace(c.Mode), ModeFakeIP) }

func (c Config) NormalizedServers(fallback string) []string {
	out := make([]string, 0, len(c.Servers))
	for _, s := range c.Servers {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		if f := strings.TrimSpace(fallback); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (c Config) NormalizedFilter() []string {
	out := make([]string, 0, len(c.FakeIPFilter))
	for _, f := range c.FakeIPFilter {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
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
