package xrayconfig

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"

	xrayNet "github.com/xtls/xray-core/common/net"
	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

const (
	dnsOutboundTag = "dns-out"
	// The module's own upstream queries. Untagged, they would hit the app :53
	// rule under fake-ip and get fake IPs, so the direct path dials the fake
	// pool (blackhole). The tiers name this inbound so they apply to them.
	dnsInternalTag = "dns-internal"

	// v4 pool: upper /16 of xray's default 198.18.0.0/15, clear of the Windows
	// TUN's own 198.18.0.1. The v6 pool is mandatory even on a v4-only TUN -
	// without it AAAA falls through to a real resolver and native IPv6 leaks
	// around the tunnel.
	fakeIPv4Pool   = "198.19.0.0/16"
	fakeIPv6Pool   = "fc00::/18"
	fakeIPPoolSize = 65535
)

// ApplyDNS reads the routing profile only to place DirectServers (normal mode
// scopes them by domain rules; fake-ip needs no rules); it never emits routing
// rules from it.
func ApplyDNS(cfg *xrayConf.Config, dns dnsconfig.Config, prof RoutingProfile) {
	if dns.FakeIP() {
		applyFakeDNS(cfg, dns, prof)
		return
	}
	applyPlainDNS(cfg, dns, prof)
}

// DisableIPv6 -> UseIPv4: only A records are resolved/answered, so the app
// never receives a v6 address (stronger than routing-blocking v6 flows).
func queryStrategy(dns dnsconfig.Config) string {
	if dns.DisableIPv6 {
		return "UseIPv4"
	}
	return ""
}

func applyPlainDNS(cfg *xrayConf.Config, dns dnsconfig.Config, prof RoutingProfile) {
	general := plainNameServers(dns.NormalizedServers(""))
	nsList := general
	if direct := plainNameServers(dns.NormalizedDirectServers()); len(direct) > 0 {
		// No fakedns here to fall through, so the split is expressed with
		// per-server domain scopes. A proxy-scoped copy of the general list
		// goes first: scopes are flat while routing is tiered, so a name an
		// earlier tier proxies (vk.ru under a later domain:ru direct rule)
		// must not be pinned to the direct resolver. The unscoped general list
		// stays last, so an unreachable direct resolver degrades to it instead
		// of making the name unresolvable.
		proxyScoped := scopedCopies(general, tierDomains(prof, routing.TargetProxy))
		switch {
		case prof.ResolvedMode() == ModeDirectAll:
			// Catch-all is direct: the direct resolvers answer by default.
			nsList = append(append(proxyScoped, direct...), general...)
		default:
			if domains := tierDomains(prof, routing.TargetDirect); len(domains) > 0 {
				nsList = append(append(proxyScoped, scopedCopies(direct, domains)...), general...)
			} else {
				logfmt.Warnf("[Xray][DNS] directServers ignored in normal mode: no direct domain rules to scope them to")
			}
		}
	}
	hosts := hostsWrapper(dns.NormalizedHosts())
	if len(nsList) == 0 && hosts == nil {
		if dns.DisableIPv6 {
			// No servers configured but AAAA must still be suppressed for xray's
			// internal resolution (freedom UseIP).
			cfg.DNSConfig = &xrayConf.DNSConfig{QueryStrategy: "UseIPv4"}
		}
		return
	}
	cfg.DNSConfig = &xrayConf.DNSConfig{Servers: nsList, Hosts: hosts, QueryStrategy: queryStrategy(dns), Tag: dnsInternalTag}
}

func applyFakeDNS(cfg *xrayConf.Config, dns dnsconfig.Config, prof RoutingProfile) {
	pool := `[{"ipPool":"` + fakeIPv4Pool + `","poolSize":` + strconv.Itoa(fakeIPPoolSize) + `}` +
		`,{"ipPool":"` + fakeIPv6Pool + `","poolSize":` + strconv.Itoa(fakeIPPoolSize) + `}]`
	if dns.DisableIPv6 {
		// v4-only pool: fakedns then never answers AAAA, and with UseIPv4 the real
		// resolvers don't either - IPv6 is fully dark to the app.
		pool = `[{"ipPool":"` + fakeIPv4Pool + `","poolSize":` + strconv.Itoa(fakeIPPoolSize) + `}]`
	}
	var fd xrayConf.FakeDNSConfig
	if err := json.Unmarshal([]byte(pool), &fd); err != nil {
		logfmt.Warnf("[Xray][DNS] fake-ip pool build failed, falling back to plain DNS: %v", err)
		applyPlainDNS(cfg, dns, prof)
		return
	}
	cfg.FakeDNS = &fd

	// Real resolvers for freedom's direct path (FakeEnable=false, so it skips
	// the fake pool - no resolve loop) and the filter exclusions.
	real := plainNameServers(dns.NormalizedServers("1.1.1.1"))

	// Excluded domains resolve for real (kept off fake-ip): a real server matched
	// only to those domains, placed ahead of the fakedns server. SkipFallback is
	// what confines it to them - without it xray's fallback pass walks the list
	// in order and this copy answers *every* name, ahead of fakedns, which turns
	// fake-ip off wholesale.
	var servers []*xrayConf.NameServerConfig
	if exclude := domainMatchers(dns.NormalizedFilter()); len(exclude) > 0 && len(real) > 0 {
		ns := *real[0]
		ns.Domains = exclude
		ns.SkipFallback = true
		servers = append(servers, &ns)
	}
	servers = append(servers, &xrayConf.NameServerConfig{
		Address: &xrayConf.Address{Address: xrayNet.ParseAddress("fakedns")},
	})
	// Direct resolvers sit *behind* fakedns so the app still gets fake IPs;
	// the module's own lookups skip fakedns (FakeEnable=false) and land here,
	// and those lookups are what freedom performs when it dials a direct-routed
	// name. Same reach as mihomo's direct-nameserver: no domain rules needed.
	servers = append(servers, plainNameServers(dns.NormalizedDirectServers())...)
	servers = append(servers, real...)
	cfg.DNSConfig = &xrayConf.DNSConfig{
		Servers:       servers,
		Hosts:         hostsWrapper(dns.NormalizedHosts()),
		QueryStrategy: queryStrategy(dns),
		Tag:           dnsInternalTag,
	}

	// A "dns" outbound answers intercepted queries via the built-in DNS module
	// (which yields fake IPs). Empty settings -> intercept A/AAAA, pass the rest to
	// the original destination.
	dnsSettings := json.RawMessage(`{}`)
	ensureOutbound(cfg, dnsOutboundTag, xrayConf.OutboundDetourConfig{
		Protocol: "dns",
		Tag:      dnsOutboundTag,
		Settings: &dnsSettings,
	})

	// Scoped to the app traffic tags so it doesn't also grab the module's own
	// queries.
	dnsRule := fieldRule{Port: "53", InboundTag: []string{AppTrafficTag, ForceProxyTag}, OutboundTag: dnsOutboundTag}
	rules := []json.RawMessage{dnsRule.raw()}
	// Internal queries go direct when that outbound exists; pure proxy-all has
	// none, so they fall to the default and resolve through the tunnel.
	if hasOutbound(cfg, directTag) {
		internalRule := fieldRule{InboundTag: []string{dnsInternalTag}, OutboundTag: directTag}
		rules = []json.RawMessage{internalRule.raw(), dnsRule.raw()}
	}
	if cfg.RouterConfig == nil {
		cfg.RouterConfig = &xrayConf.RouterConfig{}
	}
	cfg.RouterConfig.RuleList = append(rules, cfg.RouterConfig.RuleList...)
}

// scopedCopies restricts copies of the servers to domains; SkipFallback keeps
// them out of the rotation for every other name, and copying leaves the
// caller's unscoped entries usable elsewhere in the list.
func scopedCopies(list []*xrayConf.NameServerConfig, domains []string) []*xrayConf.NameServerConfig {
	if len(domains) == 0 {
		return nil
	}
	out := make([]*xrayConf.NameServerConfig, 0, len(list))
	for _, ns := range list {
		scoped := *ns
		scoped.Domains = domains
		scoped.SkipFallback = true
		out = append(out, &scoped)
	}
	return out
}

// tierDomains collects one target's matchers across every tier as xray domain
// syntax; IP-plane and process entries carry no name and drop out.
func tierDomains(prof RoutingProfile, t string) []string {
	var raw []string
	for _, tier := range prof.Tiers {
		switch t {
		case routing.TargetDirect:
			raw = append(raw, tier.Direct...)
		case routing.TargetProxy:
			raw = append(raw, tier.Proxy...)
		}
	}
	return domainMatchers(raw)
}

// HostAddress has unexported fields and only UnmarshalJSON as a public
// constructor, so the map reaches HostsWrapper through a JSON round-trip.
func hostsWrapper(hosts map[string][]string) *xrayConf.HostsWrapper {
	if len(hosts) == 0 {
		return nil
	}
	b, err := json.Marshal(hosts)
	if err != nil {
		logfmt.Warnf("[Xray][DNS] hosts dropped: %v", err)
		return nil
	}
	var hw xrayConf.HostsWrapper
	if err := json.Unmarshal(b, &hw); err != nil {
		logfmt.Warnf("[Xray][DNS] hosts dropped: %v", err)
		return nil
	}
	return &hw
}

func plainNameServers(servers []string) []*xrayConf.NameServerConfig {
	var nsList []*xrayConf.NameServerConfig
	for _, s := range servers {
		xs, ok := toXrayServer(s)
		if !ok {
			logfmt.Warnf("[Xray][DNS] skipping %q: xray has no DoT (use https:// or a plain IP)", s)
			continue
		}
		ns := &xrayConf.NameServerConfig{}
		// A plain resolver may carry a non-standard port ("10.0.0.1:5353");
		// xray takes the port as its own field and would otherwise read the
		// whole string as a hostname that resolves to nothing.
		if dnsconfig.Scheme(xs) == "" {
			if host, port, err := net.SplitHostPort(xs); err == nil {
				if p, perr := strconv.Atoi(port); perr == nil && p > 0 && p <= 65535 {
					xs, ns.Port = host, uint16(p)
				}
			}
		}
		ns.Address = &xrayConf.Address{Address: xrayNet.ParseAddress(xs)}
		nsList = append(nsList, ns)
	}
	return nsList
}

// domainMatchers classifies entries into xray domain matchers
// (domain/full/keyword/regexp/geosite). IP and process entries carry no name
// and are dropped - they mean nothing to a per-server domain scope. The
// profile and the fake-ip filter are validated before they reach here.
func domainMatchers(filter []string) []string {
	var domains []string
	for _, f := range filter {
		kind, val, ok := routing.Classify(f)
		if !ok {
			continue
		}
		switch kind {
		case routing.KindGeoSite:
			domains = append(domains, "geosite:"+val)
		case routing.KindDomainSuffix:
			domains = append(domains, "domain:"+val)
		case routing.KindDomainFull:
			domains = append(domains, "full:"+val)
		case routing.KindDomainKeyword:
			domains = append(domains, val)
		case routing.KindDomainRegex:
			domains = append(domains, "regexp:"+val)
		}
	}
	return domains
}

func toXrayServer(s string) (string, bool) {
	switch dnsconfig.Scheme(s) {
	case "": // plain IP/host -> UDP
		return s, true
	case "https", "h2c", "tcp":
		return s, true
	case "quic":
		return "quic+local://" + strings.TrimPrefix(s, "quic://"), true
	case "tls": // DoT - unsupported by xray
		return "", false
	default:
		return s, true // pass advanced schemes (https+local, tcp+local, …) through
	}
}
