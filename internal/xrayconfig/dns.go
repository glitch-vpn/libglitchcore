package xrayconfig

import (
	"encoding/json"
	"log"
	"strconv"
	"strings"

	xrayNet "github.com/xtls/xray-core/common/net"
	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

const (
	dnsOutboundTag = "dns-out"
	// Untagged, the module's own upstream queries hit the app :53 rule and get
	// fake IPs, so the direct path dials the fake pool (blackhole).
	dnsInternalTag = "dns-internal"

	// v4 pool: upper /16 of xray's default 198.18.0.0/15, clear of the Windows
	// TUN's own 198.18.0.1. The v6 pool is mandatory even on a v4-only TUN -
	// without it AAAA falls through to a real resolver and native IPv6 leaks
	// around the tunnel.
	fakeIPv4Pool   = "198.19.0.0/16"
	fakeIPv6Pool   = "fc00::/18"
	fakeIPPoolSize = 65535
)

func ApplyDNS(cfg *xrayConf.Config, dns dnsconfig.Config) {
	if dns.FakeIP() {
		applyFakeDNS(cfg, dns)
		return
	}
	applyPlainDNS(cfg, dns)
}

// DisableIPv6 -> UseIPv4: only A records are resolved/answered, so the app
// never receives a v6 address (stronger than routing-blocking v6 flows).
func queryStrategy(dns dnsconfig.Config) string {
	if dns.DisableIPv6 {
		return "UseIPv4"
	}
	return ""
}

func applyPlainDNS(cfg *xrayConf.Config, dns dnsconfig.Config) {
	nsList := plainNameServers(dns.NormalizedServers(""))
	if len(nsList) == 0 {
		if dns.DisableIPv6 {
			// No servers configured but AAAA must still be suppressed for xray's
			// internal resolution (freedom UseIP).
			cfg.DNSConfig = &xrayConf.DNSConfig{QueryStrategy: "UseIPv4"}
		}
		return
	}
	cfg.DNSConfig = &xrayConf.DNSConfig{Servers: nsList, QueryStrategy: queryStrategy(dns)}
}

func applyFakeDNS(cfg *xrayConf.Config, dns dnsconfig.Config) {
	pool := `[{"ipPool":"` + fakeIPv4Pool + `","poolSize":` + strconv.Itoa(fakeIPPoolSize) + `}` +
		`,{"ipPool":"` + fakeIPv6Pool + `","poolSize":` + strconv.Itoa(fakeIPPoolSize) + `}]`
	if dns.DisableIPv6 {
		// v4-only pool: fakedns then never answers AAAA, and with UseIPv4 the real
		// resolvers don't either - IPv6 is fully dark to the app.
		pool = `[{"ipPool":"` + fakeIPv4Pool + `","poolSize":` + strconv.Itoa(fakeIPPoolSize) + `}]`
	}
	var fd xrayConf.FakeDNSConfig
	if err := json.Unmarshal([]byte(pool), &fd); err != nil {
		log.Printf("[Xray][DNS] fake-ip pool build failed, falling back to plain DNS: %v", err)
		applyPlainDNS(cfg, dns)
		return
	}
	cfg.FakeDNS = &fd

	// Real resolvers for freedom's direct path (FakeEnable=false, so it skips
	// the fake pool - no resolve loop) and the filter exclusions.
	real := plainNameServers(dns.NormalizedServers("1.1.1.1"))

	var servers []*xrayConf.NameServerConfig
	// Excluded domains resolve for real (kept off fake-ip): a real server matched
	// only to those domains, placed ahead of the fakedns server.
	if exclude := fakeDNSExcludeDomains(dns.NormalizedFilter()); len(exclude) > 0 && len(real) > 0 {
		ns := *real[0]
		ns.Domains = exclude
		servers = append(servers, &ns)
	}
	servers = append(servers, &xrayConf.NameServerConfig{
		Address: &xrayConf.Address{Address: xrayNet.ParseAddress("fakedns")},
	})
	servers = append(servers, real...)
	cfg.DNSConfig = &xrayConf.DNSConfig{Servers: servers, QueryStrategy: queryStrategy(dns), Tag: dnsInternalTag}

	// A "dns" outbound answers intercepted queries via the built-in DNS module
	// (which yields fake IPs). Empty settings -> intercept A/AAAA, pass the rest to
	// the original destination.
	dnsSettings := json.RawMessage(`{}`)
	ensureOutbound(cfg, dnsOutboundTag, xrayConf.OutboundDetourConfig{
		Protocol: "dns",
		Tag:      dnsOutboundTag,
		Settings: &dnsSettings,
	})

	// Scoped to app inbounds so it doesn't also grab the module's own queries.
	dnsRule := fieldRule{Port: "53", InboundTag: []string{"tun2socks", forceProxyTag}, OutboundTag: dnsOutboundTag}
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

func plainNameServers(servers []string) []*xrayConf.NameServerConfig {
	var nsList []*xrayConf.NameServerConfig
	for _, s := range servers {
		xs, ok := toXrayServer(s)
		if !ok {
			log.Printf("[Xray][DNS] skipping %q: xray has no DoT (use https:// or a plain IP)", s)
			continue
		}
		nsList = append(nsList, &xrayConf.NameServerConfig{
			Address: &xrayConf.Address{Address: xrayNet.ParseAddress(xs)},
		})
	}
	return nsList
}

// fakeDNSExcludeDomains classifies filter entries into xray domain matchers
// (domain/full/keyword/regexp/geosite). IP and process entries are meaningless
// for fake-ip exclusion and are dropped.
func fakeDNSExcludeDomains(filter []string) []string {
	var domains []string
	for _, f := range filter {
		kind, val, ok := routing.Classify(f)
		if !ok {
			continue
		}
		switch kind {
		case routing.KindGeoSite:
			if routing.ValidGeoCode(val) {
				domains = append(domains, "geosite:"+val)
			}
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
