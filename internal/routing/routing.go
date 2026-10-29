// Package routing is the engine-neutral routing intent (proxy/direct/block matchers).
package routing

import (
	"errors"
	"fmt"
	"net"
	"slices"
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

// Tier is one rule group; Steps gives the rules it is evaluated as.
type Tier struct {
	Block  []string `json:"block,omitempty"`
	Direct []string `json:"direct,omitempty"`
	Proxy  []string `json:"proxy,omitempty"`
}

// Profile priority: kill-switches -> per-app VPN flows (the bridge's
// always-tunnel path) -> Tiers in order, each as its Steps -> local networks
// -> Mode catch-all. Inside a tier an entry naming one site is an exception to
// a broader entry with another outcome, and a block yields only to a more
// specific entry of its own plane (Tier.Steps). A per-app VPN flow meets every
// tier's block, whichever tier holds it, in the same order, then the local
// networks when LocalNetworks is set; every other outcome becomes proxy. An
// exception carved out of a block therefore does not reach a per-app VPN flow:
// that path fails closed. Local networks apply to a flow addressed by IP: a
// flow addressed by a name never goes direct on them.
type Profile struct {
	Mode  string
	Tiers []Tier
	// DomainStrategy feeds xray's router: AsIs ("", the default) never
	// resolves a name for routing, IPIfNonMatch resolves one no domain rule
	// matched, IPOnDemand one at its first IP rule. In proxy-all mode a
	// resolved name goes direct on a geoip or CIDR entry only to an address
	// the entry holds.
	// mihomo has no equivalent knob and ignores it.
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
// splits a mihomo rule line, a parenthesis that splits a mihomo logic rule, a
// geo code neither engine can look up, and a keyword that xray would read as
// another matcher.
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
		if !parenthesesPair(val) {
			return errUnpairedParentheses
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
		if !parenthesesPair(val) {
			return errUnpairedParentheses
		}
	}
	return nil
}

var errUnpairedParentheses = errors.New("parentheses must pair up, escaped ones included: mihomo reads them when it nests a rule")

func parenthesesPair(s string) bool {
	depth := 0
	for _, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			if depth--; depth < 0 {
				return false
			}
		}
	}
	return depth == 0
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

// Entry is one tier entry with the outcome its list gives it.
type Entry struct {
	Kind   MatchKind
	Value  string // as Classify returns it
	Target string // TargetBlock | TargetDirect | TargetProxy
}

// ByAddress: the entry matches a flow's address, not its name or its app.
func (e Entry) ByAddress() bool {
	return e.Kind == KindIPCIDR || e.Kind == KindGeoIP
}

type plane int

const (
	planeName plane = iota
	planeAddress
	planeApp
)

func (e Entry) plane() plane {
	switch {
	case e.Kind == KindProcess:
		return planeApp
	case e.ByAddress():
		return planeAddress
	}
	return planeName
}

// Step is one first-match rule of a tier. A flow matches it when it matches
// one of Entries, all of one plane and outcome, and, when Also is set, one of
// Also, all of the other plane.
type Step struct {
	Entries []Entry
	Also    []Entry
	Target  string
}

// Steps is the tier as first-match rules, in Entries order. A block yields
// only to a more specific entry of its own plane, names or addresses; between
// the planes a block beats direct and proxy. So each direct or proxy run is
// preceded by steps pairing it with the other plane's entries up to that
// plane's last block: a block there takes the flow, unless an entry of that
// plane more specific than the block, which keeps the run's outcome, comes
// first.
func (t Tier) Steps() []Step {
	entries := t.Entries()
	byPlane := map[plane][]Entry{}
	for _, e := range entries {
		byPlane[e.plane()] = append(byPlane[e.plane()], e)
	}
	other := map[plane]plane{planeName: planeAddress, planeAddress: planeName}
	var steps []Step
	for i := 0; i < len(entries); {
		j := i + 1
		for j < len(entries) && entries[j].plane() == entries[i].plane() && entries[j].Target == entries[i].Target {
			j++
		}
		run, target := entries[i:j:j], entries[i].Target
		if otherPlane, paired := other[run[0].plane()]; paired && target != TargetBlock {
			steps = append(steps, guardSteps(run, target, byPlane[otherPlane])...)
		}
		steps = append(steps, Step{Entries: run, Target: target})
		i = j
	}
	return steps
}

func guardSteps(run []Entry, target string, otherPlane []Entry) []Step {
	last := -1
	for k, e := range otherPlane {
		if e.Target == TargetBlock {
			last = k
		}
	}
	if last < 0 {
		return nil
	}
	var steps []Step
	for _, e := range otherPlane[:last+1] {
		outcome := target
		if e.Target == TargetBlock {
			outcome = TargetBlock
		}
		if n := len(steps); n > 0 && steps[n-1].Target == outcome {
			steps[n-1].Also = append(steps[n-1].Also, e)
			continue
		}
		steps = append(steps, Step{Entries: run, Also: []Entry{e}, Target: outcome})
	}
	return steps
}

// Entries is the tier's entries in evaluation order, first match wins, the
// more specific entry first: full:, domain: (more labels first), an IP or CIDR
// (the narrower first), keyword: and regexp:, then the categories geosite: and
// geoip: as one rank. At equal rank block beats direct beats proxy, so between
// two categories the outcome decides. A process: entry is not a site: its
// block leads the tier and its direct or proxy closes it. Breadth splits only entries that can overlap (a
// domain: by labels, a CIDR by prefix), so xray keeps few field rules. Entries
// Classify refuses are left out.
func (t Tier) Entries() []Entry {
	var entries []Entry
	for _, list := range []struct {
		matchers []string
		target   string
	}{{t.Block, TargetBlock}, {t.Direct, TargetDirect}, {t.Proxy, TargetProxy}} {
		for _, m := range list.matchers {
			if kind, val, ok := Classify(m); ok {
				entries = append(entries, Entry{Kind: kind, Value: val, Target: list.target})
			}
		}
	}
	slices.SortStableFunc(entries, func(a, b Entry) int {
		keyA, keyB := a.evaluationKey(), b.evaluationKey()
		return slices.Compare(keyA[:], keyB[:])
	})
	return entries
}

// evaluationKey orders by section (app block, sites and categories, other app
// entries), then rank, then breadth inside the rank, then outcome.
func (e Entry) evaluationKey() [4]int {
	outcome := 2
	switch e.Target {
	case TargetBlock:
		outcome = 0
	case TargetDirect:
		outcome = 1
	}
	switch e.Kind {
	case KindProcess:
		if e.Target == TargetBlock {
			return [4]int{0, 0, 0, outcome}
		}
		return [4]int{2, 0, 0, outcome}
	case KindDomainFull:
		return [4]int{1, 0, 0, outcome}
	case KindDomainSuffix:
		return [4]int{1, 1, -strings.Count(e.Value, "."), outcome}
	case KindIPCIDR:
		return [4]int{1, 2, hostBits(e.Value), outcome}
	case KindDomainKeyword, KindDomainRegex:
		return [4]int{1, 3, 0, outcome}
	default: // KindGeoSite, KindGeoIP
		return [4]int{1, 4, 0, outcome}
	}
}

func hostBits(ipOrCIDR string) int {
	_, network, err := net.ParseCIDR(NormalizeCIDR(ipOrCIDR))
	if err != nil {
		return 0
	}
	ones, bits := network.Mask.Size()
	return bits - ones
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
