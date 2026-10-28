// Package routing is the engine-neutral routing intent (proxy/direct/block matchers).
package routing

import (
	"errors"
	"fmt"
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

// ProcessRules: process:NAME -> target. Mihomo uses PROCESS-NAME, or
// PROCESS-NAME-REGEX for a name holding a comma; xray applies
// direct/block in the tun2socks dialer (xray can't see the real app behind it).
// The dialer consumes one flat map, so tier order cannot apply to process:
// rules - only the global priority block > direct > proxy does (later writes win).
func ProcessRules(p Profile) map[string]string {
	out := map[string]string{}
	add := func(list []string, target string) {
		for _, m := range list {
			if kind, val, ok := Classify(m); ok && kind == KindProcess {
				out[strings.ToLower(strings.TrimSpace(val))] = target
			}
		}
	}
	for _, t := range p.Tiers {
		add(t.Proxy, TargetProxy)
	}
	for _, t := range p.Tiers {
		add(t.Direct, TargetDirect)
	}
	for _, t := range p.Tiers {
		add(t.Block, TargetBlock)
	}
	return out
}

// LocalNetworkCIDRs are routed direct so LAN/router/loopback stay reachable
// while the tunnel is up.
var LocalNetworkCIDRs = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
	"169.254.0.0/16", "127.0.0.0/8", "fc00::/7", "fe80::/10", "::1/128",
}

// Tier is one ordered rule group; within a tier block beats direct beats proxy.
type Tier struct {
	Block  []string `json:"block,omitempty"`
	Direct []string `json:"direct,omitempty"`
	Proxy  []string `json:"proxy,omitempty"`
}

// Profile priority: kill-switches -> per-app VPN flows (the bridge's
// always-tunnel path) -> Tiers in order (block -> direct -> proxy within each)
// -> local networks -> Mode catch-all. A per-app VPN flow meets every tier's
// block, whichever tier holds it, then the local networks when LocalNetworks is
// set; every other outcome becomes proxy. Local networks apply to a flow
// addressed by IP: a flow addressed by a name never goes direct on them.
type Profile struct {
	Mode  string
	Tiers []Tier
	// DomainStrategy feeds xray's router-level domainStrategy (whether the
	// router resolves domain-form requests to match IP rules); "" = engine
	// default (AsIs). mihomo has no equivalent knob and ignores it.
	DomainStrategy    string
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

func (p Profile) HasDirect() bool {
	for _, t := range p.Tiers {
		if len(t.Direct) > 0 {
			return true
		}
	}
	return false
}

func (p Profile) HasBlock() bool {
	for _, t := range p.Tiers {
		if len(t.Block) > 0 {
			return true
		}
	}
	return false
}

// Validate refuses what the engines would cut, re-target or drop: a comma that
// splits a mihomo rule line, a geo code neither engine can look up, and a keyword
// that xray would read as another matcher.
func (p Profile) Validate() error {
	for i, t := range p.Tiers {
		for _, list := range [][]string{t.Block, t.Direct, t.Proxy} {
			for _, m := range list {
				if err := validateMatcher(m); err != nil {
					return fmt.Errorf("tier %d: %q: %w", i+1, m, err)
				}
			}
		}
	}
	return nil
}

func validateMatcher(m string) error {
	kind, val, ok := Classify(m)
	if !ok {
		return nil
	}
	switch kind {
	case KindDomainSuffix, KindDomainFull, KindDomainKeyword:
		if strings.Contains(val, ",") {
			return errors.New("a domain cannot contain a comma")
		}
		if kind == KindDomainKeyword {
			if err := ValidKeyword(val); err != nil {
				return err
			}
		}
	case KindGeoSite:
		if !ValidGeoCode(val) {
			return errors.New("invalid geosite code: ASCII letters, digits, '-', '_', '!' and '@' only, no leading '!'")
		}
	case KindGeoIP:
		if !ValidGeoIPCode(val) {
			return errors.New("invalid geoip code: ASCII letters, digits, '-' and '_' only, with an optional leading '!'")
		}
	case KindDomainRegex:
		if strings.Contains(val, " ,") || strings.Contains(val, ", ") {
			return errors.New("a regexp cannot have a space beside a comma")
		}
	}
	return nil
}

// xrayMatcherPrefixes are the prefixes xray's domain rule parser reads as a
// matcher type; a bare value starting with one is no longer a plain keyword.
var xrayMatcherPrefixes = []string{
	"regexp:", "domain:", "full:", "keyword:", "dotless:",
	"geosite:", "ext:", "ext-domain:", "ext-site:",
}

// ValidKeyword refuses a keyword xray would read as another matcher.
func ValidKeyword(val string) error {
	for _, prefix := range xrayMatcherPrefixes {
		if strings.HasPrefix(val, prefix) {
			return fmt.Errorf("a keyword cannot start with %q, which xray reads as another matcher", prefix)
		}
	}
	return nil
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
			return domainEntry(KindDomainSuffix, val)
		case "full":
			return domainEntry(KindDomainFull, val)
		case "keyword":
			return KindDomainKeyword, val, true
		case "regexp", "regex":
			return KindDomainRegex, val, true
		case "process":
			return KindProcess, val, true
		}
	}
	return domainEntry(KindDomainSuffix, e)
}

// domainEntry strips the dots callers habitually wrap a zone in (".ru",
// "example.ru."). Both engines match domains on label boundaries, so either
// dot would make the rule match nothing at all - and a rule that silently
// never applies is worse than a rejected one. Keyword (substring) and regex
// values keep their dots.
func domainEntry(kind MatchKind, val string) (MatchKind, string, bool) {
	val = strings.Trim(val, ".")
	if val == "" {
		return 0, "", false
	}
	return kind, val, true
}

func isIPOrCIDR(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// ValidGeoCode (geosite): ASCII letters/digits/hyphen/underscore, plus '!'
// (literal in category names like geolocation-!cn) and '@' (xray attribute
// qualifier, cn@ads). Non-ASCII would fail the whole config. Empty segments
// around '@' are rejected - xray parses them as empty attributes. A *leading*
// '!' is rejected too: mihomo reads it as inverse match, xray looks up a list
// literally named "!CN" and hard-fails the whole config.
func ValidGeoCode(code string) bool {
	code = strings.TrimSpace(code)
	if code == "" || strings.HasPrefix(code, "!") {
		return false
	}
	for _, seg := range strings.Split(code, "@") {
		if seg == "" || !validGeoChars(seg, "!") {
			return false
		}
	}
	return true
}

// ValidGeoIPCode: optional leading '!' (xray inverse match), then the plain
// charset. geoip has no attribute syntax, so '@' stays rejected - it would
// fail the whole config at build time.
func ValidGeoIPCode(code string) bool {
	code = strings.TrimSpace(code)
	code = strings.TrimPrefix(code, "!")
	return code != "" && validGeoChars(code, "")
}

func validGeoChars(s, extra string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' ||
			strings.ContainsRune(extra, r)) {
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
