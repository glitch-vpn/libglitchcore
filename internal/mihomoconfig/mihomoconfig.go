// Package mihomoconfig builds a mihomo *config.Config from share links (no YAML round-trip).
package mihomoconfig

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/vlessencryption"
	"github.com/glitch-vpn/libglitchcore/internal/vmesslink"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	T "github.com/metacubex/mihomo/tunnel"
)

const (
	// Balancer proxy group; the selection watcher looks it up in tunnel.Proxies().
	GroupTag = "vpn"
	// Matches the xray observatory default probe URL.
	probeURL = "https://www.gstatic.com/generate_204"

	fakeIPRange = "198.18.0.1/16"
	// Same v6 pool as xray's fakedns (xrayconfig/dns.go).
	fakeIPRange6 = "fc00::/18"

	// Bridge-path pool: clear of the wireguard/Wintun TUN's own 198.18.0.1, yet
	// still inside its 128.0.0.0/1 split-default so fake IPs route in.
	fakeIPRangeBridge = "198.19.0.0/16"
)

// TunInbound: Android adopts a VpnService fd; desktop creates the adapter.
type TunInbound struct {
	FileDescriptor int    // > 0 -> adopt this fd (Android VpnService)
	Device         string // desktop adapter name (e.g. "GlitchVPN")
	MTU            int
	DNS            dnsconfig.Config
}

// Inbound: loopback mixed (proxy mode), the core's tun2socks bridge, or
// native TUN.
type Inbound struct {
	MixedPort int         // > 0 -> loopback socks/http on 127.0.0.1
	Tun       *TunInbound // non-nil -> native TUN inbound
	// Bridge: the core's tun2socks bridge hands mihomo's tunnel the TUN's
	// flows in process.
	Bridge bool
	// Windows bridge: bind outbounds to the physical NIC, not our TUN.
	Interface string
	// ForceProxy adds the rule that always tunnels flows named
	// ForceProxyInName (the bridge's process->proxy dialer).
	ForceProxy bool
	// Proxy-mode and bridge DNS (native TUN uses TunInbound.DNS). With
	// fake-ip on the bridge, mihomo's resolver answers the :53 the bridge
	// hands it.
	DNS dnsconfig.Config
	// ProxyUser and ProxyPass gate MixedPort, which then carries TCP only.
	// Empty leaves it open, which only a caller's proxy mode without
	// credentials asks for.
	ProxyUser, ProxyPass string
}

// ForceProxyInName is the inbound name the bridge's force-proxy flows carry.
const ForceProxyInName = "forceproxy"

// forceFlowsSubRule names the sub-rule that holds the force-proxy flows' rules.
const forceFlowsSubRule = "force-flows"

// ProxyInName names the proxy-mode listener that carries credentials.
const ProxyInName = "proxy"

type Options struct {
	Strategy string // balancer group type ("" = url-test)
	// DisableSniffing: domains then come only from DNS - flows that bypass it
	// lose domain-rule matching; in normal DNS mode domain routing stops entirely.
	DisableSniffing bool
	ProbeURL        string // balancer health-check URL ("" = generate_204)
	// Per-proxy uTLS fingerprint (mihomo dropped global-client-fingerprint in v1.19).
	Fingerprint string
}

// uTLS fingerprints mihomo accepts (differs from xray's set).
var MihomoFingerprints = []string{
	"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
	"random", "randomized", "chrome120", "firefox120", "safari16",
}

func ValidFingerprint(fp string) bool {
	for _, f := range MihomoFingerprints {
		if f == fp {
			return true
		}
	}
	return false
}

// BuildConfig: one link -> that proxy; multiple -> balancer group.
func BuildConfig(links []string, in Inbound, opts Options, prof routing.Profile) (*config.Config, error) {
	if in.MixedPort <= 0 && in.Tun == nil && !in.Bridge {
		return nil, fmt.Errorf("no inbound: set MixedPort, Tun or Bridge")
	}

	raw := config.DefaultRawConfig()
	raw.AllowLan = false
	raw.Mode = T.Rule
	// The core reads mihomo's events through its subscription; its own printer
	// stays off, from the moment ApplyConfig sets this level.
	raw.LogLevel = log.SILENT
	if prof.DisableIPv6 {
		// Resolver stops returning AAAA; the ::/0 REJECT (buildRules) kills v6
		// flows that arrive as literals.
		raw.IPv6 = false
	}
	// v2fly .dat from the home dir; the caller owns the files. GeoAutoUpdate
	// only governs the periodic updater - mihomo also bootstraps a missing or
	// unverifiable .dat by downloading it when a GEOSITE/GEOIP rule is parsed
	// (rules/common/geosite.go -> geodata.InitGeoSite). Blanking the URLs turns
	// that fetch into a start failure: fetching geo data behind the caller's
	// back is not an engine's call to make.
	raw.GeodataMode = true
	raw.GeoAutoUpdate = false
	raw.GeoXUrl = config.RawGeoXUrl{}
	// The IP->domain mapping lives in the DNS layer, so switching the sniffer
	// off never breaks fake-ip itself. ParsePureIp is what makes the sniffer
	// act on a flow addressed by IP; without it only force-domain names would
	// be sniffed. OverrideDest stays off so the dial keeps the IP and the name
	// only steers the rules, as xray's routeOnly does. ForceDnsMapping stays
	// off: a name DNS already supplied is authoritative, and sniffing would
	// let the app's own bytes disagree with it.
	raw.Sniffer = config.RawSniffer{
		Enable:       !opts.DisableSniffing,
		ParsePureIp:  true,
		OverrideDest: false,
		Sniff: map[string]config.RawSniffingConfig{
			"TLS":  {Ports: []string{"443"}},
			"HTTP": {Ports: []string{"80", "8080-8880"}},
			"QUIC": {Ports: []string{"443"}},
		},
	}
	if prof.LocalNetworks {
		// A local destination keeps its address-based routing instead of being
		// re-routed by a name read from its traffic. Fake-ip restoration is not
		// the sniffer's, so it is unaffected.
		raw.Sniffer.SkipDstAddress = routing.LocalNetworkCIDRs
	}

	if in.MixedPort > 0 {
		if in.ProxyUser != "" && in.ProxyPass != "" {
			// UDP off: SOCKS5 UDP is not bound to the authenticated
			// connection, so the credentials could not cover it.
			raw.Listeners = append(raw.Listeners, map[string]any{
				"name":   ProxyInName,
				"type":   "mixed",
				"listen": "127.0.0.1",
				"port":   in.MixedPort,
				"users":  []map[string]any{{"username": in.ProxyUser, "password": in.ProxyPass}},
				"udp":    false,
			})
		} else {
			raw.MixedPort = in.MixedPort // allow-lan:false forces it onto 127.0.0.1
		}
	}
	if in.MixedPort > 0 || in.Bridge {
		applyHosts(raw, in.DNS)
	}
	if in.Bridge {
		applyBridgeDNS(raw, in.DNS)
	}
	if in.Interface != "" {
		raw.Interface = in.Interface
	}
	if in.Tun != nil {
		applyTun(raw, in.Tun)
		applyHosts(raw, in.Tun.DNS)
	}

	names := ProxyNames(links)
	ni := 0
	for i, link := range links {
		trimmed := strings.TrimSpace(link)
		if trimmed == "" {
			continue
		}
		proxy, err := proxyFromLink(trimmed, names[ni])
		ni++
		if err != nil {
			return nil, fmt.Errorf("link %d: %w", i, err)
		}
		applyProxyFingerprint(proxy, opts.Fingerprint)
		raw.Proxy = append(raw.Proxy, proxy)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no links provided")
	}

	target := Target(links)
	if len(names) > 1 {
		group, err := balancerGroup(names, opts.Strategy, opts.ProbeURL)
		if err != nil {
			return nil, err
		}
		raw.ProxyGroup = []map[string]any{group}
	}

	rules := append(fakePoolRejectRules(raw), buildRules(prof, target, in.ForceProxy)...)
	raw.Rule = rules
	geoRules := rules
	if in.ForceProxy && forceFlowsNeedSubRule(prof) {
		raw.SubRules = map[string][]string{forceFlowsSubRule: forceFlowRules(prof, target)}
		geoRules = append(append([]string{}, rules...), raw.SubRules[forceFlowsSubRule]...)
	}

	if err := checkGeoAssets(geoRules, raw.DNS.FakeIPFilter); err != nil {
		return nil, err
	}
	return config.ParseRawConfig(raw)
}

// checkGeoAssets validates the caller's .dat files before mihomo reaches its
// own bootstrap path. That path does not just download: a file that fails
// mihomo's CN-load check is **deleted** first, and with the URLs blanked
// nothing replaces it - so a slimmed or truncated file supplied by the caller
// would be destroyed. Verifying here fails the start with the file intact.
func checkGeoAssets(rules, fakeIPFilter []string) error {
	var needSite, needIP bool
	for _, r := range rules {
		switch {
		case strings.HasPrefix(r, "GEOSITE,"):
			needSite = true
		case strings.HasPrefix(r, "GEOIP,"):
			needIP = true
		}
	}
	for _, f := range fakeIPFilter {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(f)), "geosite:") {
			needSite = true
		}
	}
	// C.Path resolves these against the home dir the caller's asset dir set,
	// and sets C.GeositeName/C.GeoipName to the filenames it found.
	if needSite {
		if err := requireGeoFile(C.Path.GeoSite(), C.GeositeName, "geosite.dat"); err != nil {
			return err
		}
	}
	if needIP {
		if err := requireGeoFile(C.Path.GeoIP(), C.GeoipName, "geoip.dat"); err != nil {
			return err
		}
	}
	return nil
}

func requireGeoFile(path, listName, label string) error {
	st, err := os.Stat(path)
	if path == "" || err != nil || st.IsDir() {
		return fmt.Errorf("%s not found (looked for %q); the caller supplies geo assets", label, path)
	}
	if err := geodata.Verify(listName); err != nil {
		return fmt.Errorf("%s at %q is unusable by mihomo (it validates by loading the \"cn\" list): %w", label, path, err)
	}
	return nil
}

// buildRules translates the routing profile into mihomo rule lines. target is
// where unlisted traffic goes; an empty profile yields just MATCH,target.
// Priority (first match wins): kill-switches -> tiers in order, each as its
// routing.Tier.Steps -> local -> mode catch-all. forceProxy adds the
// bridge's always-tunnel flows right after the kill-switches: they meet every
// tier's block and the local networks, then reach the proxy even in direct-all
// mode.
func buildRules(p routing.Profile, target string, forceProxy bool) []string {
	var rules []string
	if p.DisableIPv6 {
		rules = append(rules, "IP-CIDR,::/0,REJECT,no-resolve")
	}
	if p.DisableUDP {
		// :53 stays open so DNS keeps resolving.
		rules = append(rules, "AND,((NETWORK,udp),(NOT,((DST-PORT,53)))),REJECT")
	}
	if forceProxy {
		if forceFlowsNeedSubRule(p) {
			rules = append(rules, "SUB-RULE,(IN-NAME,"+ForceProxyInName+"),"+forceFlowsSubRule)
		} else {
			rules = append(rules, "IN-NAME,"+ForceProxyInName+","+target)
		}
		// mihomo skips a matched rule whose proxy lacks UDP and moves on to the
		// next one; this keeps such a flow from falling through to the tiers.
		rules = append(rules, "IN-NAME,"+ForceProxyInName+",REJECT")
	}
	outcomes := map[string]string{routing.TargetBlock: "REJECT", routing.TargetDirect: "DIRECT", routing.TargetProxy: target}
	for _, tier := range p.Tiers {
		for _, step := range tier.Steps() {
			rules = append(rules, stepLines(step, outcomes[step.Target])...)
		}
	}
	catchAll := target
	if p.ResolvedMode() == routing.ModeDirectAll {
		catchAll = "DIRECT"
	}
	if p.LocalNetworks {
		// DIRECT dials the flow's host when it has one, so only a flow without
		// a name goes direct on a local address.
		rules = append(rules, "DOMAIN-REGEX,.,"+catchAll)
		for _, cidr := range routing.LocalNetworkCIDRs {
			rules = append(rules, "IP-CIDR,"+cidr+",DIRECT,no-resolve")
		}
	}
	rules = append(rules, "MATCH,"+catchAll)
	return rules
}

// fakePoolRejectRules refuses a flow still addressed by a fake-ip: one whose
// record is gone. The sniffer would read a name from its bytes and route it by
// that name, dialing the fake address. A flow whose record exists has had its
// address cleared for its name, so no address rule matches it. The rules lead
// the list, so every flow, force-proxy ones included, meets them first.
func fakePoolRejectRules(raw *config.RawConfig) []string {
	if raw.DNS.EnhancedMode != C.DNSFakeIP {
		return nil
	}
	var rules []string
	for _, pool := range []string{raw.DNS.FakeIPRange, raw.DNS.FakeIPRange6} {
		if pool != "" {
			rules = append(rules, "IP-CIDR,"+routing.NormalizeCIDR(pool)+",REJECT,no-resolve")
		}
	}
	return rules
}

// forceFlowsNeedSubRule: the force-proxy flows go straight to the proxy unless
// a tier blocks something or local networks are sent direct.
func forceFlowsNeedSubRule(p routing.Profile) bool {
	return p.HasBlock() || p.LocalNetworks
}

// forceFlowRules is the sub-rule the force-proxy flows enter: every tier's
// block entries in tier order, the local networks when the profile sends them
// direct, then the proxy. Only those flows see it.
func forceFlowRules(p routing.Profile, target string) []string {
	var rules []string
	for _, tier := range p.Tiers {
		for _, step := range tier.Steps() {
			if step.Target == routing.TargetBlock && len(step.Also) == 0 {
				rules = append(rules, stepLines(step, "REJECT")...)
			}
		}
	}
	if p.LocalNetworks {
		rules = append(rules, "DOMAIN-REGEX,.,"+target)
		for _, cidr := range routing.LocalNetworkCIDRs {
			rules = append(rules, "IP-CIDR,"+cidr+",DIRECT,no-resolve")
		}
	}
	return append(rules, "MATCH,"+target)
}

// stepLines is the step as mihomo rule lines routing to target: one line per
// entry, or, for a step pairing two planes, one AND line.
func stepLines(step routing.Step, target string) []string {
	if len(step.Also) == 0 {
		var lines []string
		for _, e := range step.Entries {
			if condition := ruleCondition(e, target); condition != "" {
				lines = append(lines, condition)
			}
		}
		return lines
	}
	entries, also := anyOf(step.Entries), anyOf(step.Also)
	if entries == "" || also == "" {
		return nil
	}
	return []string{"AND,(" + entries + "," + also + ")," + target}
}

// anyOf is a logic rule operand matching any of the entries.
func anyOf(entries []routing.Entry) string {
	var operands []string
	for _, e := range entries {
		if condition := ruleCondition(e, ""); condition != "" {
			operands = append(operands, "("+condition+")")
		}
	}
	switch len(operands) {
	case 0:
		return ""
	case 1:
		return operands[0]
	}
	return "(OR,(" + strings.Join(operands, ",") + "))"
}

// ruleCondition is the entry as a mihomo rule routing to target, or, with no
// target, as an operand of a logic rule. The core runs routing.Profile.Validate
// first, so no domain value here holds a comma that would split its line or a
// parenthesis that would split a logic rule, and no geo code is one mihomo
// cannot look up.
func ruleCondition(e routing.Entry, target string) string {
	withTarget := func(head, param string) string {
		parts := []string{head}
		if target != "" {
			parts = append(parts, target)
		}
		if param != "" {
			parts = append(parts, param)
		}
		return strings.Join(parts, ",")
	}
	switch e.Kind {
	case routing.KindGeoSite:
		return withTarget("GEOSITE,"+e.Value, "")
	case routing.KindGeoIP:
		return withTarget("GEOIP,"+e.Value, "no-resolve")
	case routing.KindDomainSuffix:
		return withTarget("DOMAIN-SUFFIX,"+e.Value, "")
	case routing.KindDomainFull:
		return withTarget("DOMAIN,"+e.Value, "")
	case routing.KindDomainKeyword:
		return withTarget("DOMAIN-KEYWORD,"+e.Value, "")
	case routing.KindDomainRegex:
		return withTarget("DOMAIN-REGEX,"+e.Value, "")
	case routing.KindIPCIDR:
		return withTarget("IP-CIDR,"+routing.NormalizeCIDR(e.Value), "no-resolve")
	case routing.KindProcess:
		return withTarget(processCondition(e.Value), "")
	}
	return ""
}

// processCondition: PROCESS-NAME reads its value from one comma-separated
// field, so a name holding a comma (legal on Windows) rides
// PROCESS-NAME-REGEX, which rejoins its fields. Spaces are spelled \x20
// because mihomo trims each field. Both forms match the whole name,
// case-insensitively.
func processCondition(name string) string {
	if !strings.Contains(name, ",") {
		return "PROCESS-NAME," + name
	}
	pattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(name), " ", `\x20`) + "$"
	return "PROCESS-NAME-REGEX," + pattern
}

// Strategies mihomo accepts (besides "" = url-test default); the plugin gates on
// this before calling the core.
var Strategies = []string{"url-test", "fallback", "load-balance", "load-balance-hash"}

// NormalizeStrategy resolves the aliases callers may pass ("" = default,
// round-robin/consistent-hashing for the load-balance variants) to one of
// [Strategies]; ok is false for anything else.
func NormalizeStrategy(strategy string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "", "url-test":
		return "url-test", true
	case "fallback":
		return "fallback", true
	case "load-balance", "round-robin":
		return "load-balance", true
	case "load-balance-hash", "consistent-hashing":
		return "load-balance-hash", true
	default:
		return "", false
	}
}

func balancerGroup(names []string, strategy, probe string) (map[string]any, error) {
	if strings.TrimSpace(probe) == "" {
		probe = probeURL
	}
	g := map[string]any{
		"name":     GroupTag,
		"proxies":  names,
		"url":      probe,
		"interval": 300,
	}
	normalized, ok := NormalizeStrategy(strategy)
	if !ok {
		return nil, fmt.Errorf("unknown mihomo balancer strategy %q", strategy)
	}
	switch normalized {
	case "load-balance":
		g["type"] = "load-balance"
		g["strategy"] = "round-robin"
	case "load-balance-hash":
		g["type"] = "load-balance"
		g["strategy"] = "consistent-hashing"
	default:
		g["type"] = normalized
	}
	return g, nil
}

// Bridge DNS: mihomo's resolver, which the bridge hands the TUN's :53.
// v4-only fake IPs - AAAA would leak real v6.
func applyBridgeDNS(raw *config.RawConfig, dns dnsconfig.Config) {
	if !dns.FakeIP() {
		return
	}
	raw.DNS.Enable = true
	raw.DNS.IPv6 = false
	raw.DNS.EnhancedMode = C.DNSFakeIP
	raw.DNS.FakeIPRange = fakeIPRangeBridge
	if filter := dns.NormalizedFilter(); len(filter) > 0 {
		raw.DNS.FakeIPFilter = filter
	}
	raw.DNS.NameServer = dns.NormalizedServers("1.1.1.1")
	if direct := dns.NormalizedDirectServers(); len(direct) > 0 {
		raw.DNS.DirectNameServer = direct
	}
}

// applyHosts fills mihomo's top-level hosts table (use-hosts defaults true).
// It runs outside the DNS appliers because mihomo publishes hosts through its
// resolver even with the DNS server off - proxy mode included.
func applyHosts(raw *config.RawConfig, dns dnsconfig.Config) {
	for k, v := range dns.NormalizedHosts() {
		raw.Hosts[k] = v
	}
}

// gVisor is the only stack that works uniformly across Android/Windows/Linux here.
func applyTun(raw *config.RawConfig, t *TunInbound) {
	mtu := t.MTU
	if mtu <= 0 {
		mtu = 1420
	}
	raw.Tun.Enable = true
	raw.Tun.Stack = C.TunGvisor
	raw.Tun.DNSHijack = []string{"any:53"}
	raw.Tun.MTU = uint32(mtu)
	// mihomo defaults to 1, one goroutine for all inbound packets; 0 lets gVisor
	// run one per processor on Linux and Android, as the tunnel is tested with.
	raw.Tun.ProcessorsPerChannel = 0

	if t.FileDescriptor > 0 {
		// Android. AutoRoute/AutoDetectInterface MUST stay off: either one makes
		// sing-tun open a netlink socket, which SELinux bans for unprivileged
		// apps and the TUN fails. VpnService already routes and excludes us.
		raw.Tun.FileDescriptor = t.FileDescriptor
		raw.Tun.AutoRoute = false
		raw.Tun.AutoDetectInterface = false
	} else {
		raw.Tun.Device = t.Device
		raw.Tun.AutoRoute = true
		raw.Tun.AutoDetectInterface = true
	}

	raw.DNS.Enable = true
	// AAAA is answered unless the caller turned IPv6 off; without it a name
	// resolves to IPv6 only for literals.
	raw.DNS.IPv6 = !t.DNS.DisableIPv6
	if t.DNS.FakeIP() {
		raw.DNS.EnhancedMode = C.DNSFakeIP
		raw.DNS.FakeIPRange = fakeIPRange
		if raw.DNS.IPv6 {
			raw.DNS.FakeIPRange6 = fakeIPRange6
		}
		if filter := t.DNS.NormalizedFilter(); len(filter) > 0 {
			raw.DNS.FakeIPFilter = filter
		}
	} else {
		raw.DNS.EnhancedMode = C.DNSNormal
	}
	// mihomo parses tls://, https://, quic://, tcp:// and plain natively.
	if servers := t.DNS.NormalizedServers(""); len(servers) > 0 {
		raw.DNS.NameServer = servers
	}
	if direct := t.DNS.NormalizedDirectServers(); len(direct) > 0 {
		raw.DNS.DirectNameServer = direct
	}
}

func applyProxyFingerprint(proxy map[string]any, fp string) {
	fp = strings.TrimSpace(fp)
	if fp == "" || !ValidFingerprint(fp) {
		return
	}
	switch proxy["type"] {
	case "vless", "vmess", "trojan", "anytls":
		proxy["client-fingerprint"] = fp
	}
}

// For the pinger's throwaway adapter.
func ProxyMapFromLink(link string) (map[string]any, error) {
	return proxyFromLink(strings.TrimSpace(link), "probe")
}

func proxyFromLink(link, name string) (map[string]any, error) {
	lower := strings.ToLower(link)
	switch {
	case strings.HasPrefix(lower, "vless://"):
		return vlessProxy(link, name)
	case strings.HasPrefix(lower, "ss://"):
		return ssProxy(link, name)
	case strings.HasPrefix(lower, "trojan://"):
		return trojanProxy(link, name)
	case strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hy2://"):
		return hysteria2Proxy(link, name)
	case strings.HasPrefix(lower, "tuic://"):
		return tuicProxy(link, name)
	case strings.HasPrefix(lower, "anytls://"):
		return anytlsProxy(link, name)
	case vmesslink.IsLink(link):
		return vmessProxy(link, name)
	case strings.HasPrefix(lower, awgconfig.LinkScheme), strings.Contains(link, "[Interface]"):
		return wireguardProxy(link, name)
	default:
		return nil, fmt.Errorf("unsupported link scheme")
	}
}

// Target is the proxy, or the balancer group over several, that proxied
// traffic goes to.
func Target(links []string) string {
	names := ProxyNames(links)
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return GroupTag
}

// Names mihomo's parser defines in every config (config.parseProxies), plus
// the balancer group. A proxy taking one of the outbounds' names fails the
// start; one named GLOBAL is replaced by mihomo's selector, which picks DIRECT.
var reservedNames = []string{
	"DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS", "PASS-RULE", "GLOBAL",
	GroupTag,
}

// Must match BuildConfig's naming exactly - callers map the group's Now()
// back to a link index through it.
func ProxyNames(links []string) []string {
	var names []string
	used := make(map[string]bool, len(reservedNames))
	for _, name := range reservedNames {
		used[name] = true
	}
	for i, link := range links {
		trimmed := strings.TrimSpace(link)
		if trimmed == "" {
			continue
		}
		names = append(names, uniqueName(linkName(trimmed, i), used))
	}
	return names
}

func linkName(link string, idx int) string {
	var frag string
	if strings.HasPrefix(strings.ToLower(link), awgconfig.LinkScheme) {
		frag = awgconfig.LinkName(link)
	} else if vmesslink.IsLink(link) {
		// ps is written as is; only the comma rule applies to it.
		l, _ := vmesslink.Parse(link)
		if name := strings.TrimSpace(strings.ReplaceAll(l.Name, ",", " ")); name != "" {
			return name
		}
		return fmt.Sprintf("proxy-%d", idx)
	} else if u, err := url.Parse(link); err == nil {
		frag = u.Fragment // url.Parse already %-decodes
	}
	if frag = sanitizeName(frag); frag != "" {
		return frag
	}
	return fmt.Sprintf("proxy-%d", idx)
}

// Commas would break rule lines; spaces/pipes/emoji are fine as proxy names.
// '+' means space in v2rayN-style remarks (url.Parse leaves it undecoded).
func sanitizeName(s string) string {
	s = strings.ReplaceAll(s, ",", " ")
	s = strings.ReplaceAll(s, "+", " ")
	return strings.TrimSpace(s)
}

// mihomo requires unique proxy names.
func uniqueName(name string, used map[string]bool) string {
	candidate := name
	for n := 2; used[candidate]; n++ {
		candidate = fmt.Sprintf("%s (%d)", name, n)
	}
	used[candidate] = true
	return candidate
}

func vlessProxy(link, name string) (map[string]any, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, logfmt.WithoutURL(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	q := u.Query()
	network := strings.ToLower(strings.TrimSpace(q.Get("type")))
	if network == "" {
		network = "tcp"
	}

	p := map[string]any{
		"name":    name,
		"type":    "vless",
		"server":  u.Hostname(),
		"port":    port,
		"uuid":    u.User.Username(),
		"udp":     true,
		"network": network,
	}
	if flow := q.Get("flow"); flow != "" {
		p["flow"] = flow
	}
	encryption, err := vlessencryption.Normalize(q.Get("encryption"))
	if err != nil {
		return nil, err
	}
	if encryption != vlessencryption.None {
		p["encryption"] = encryption
	}

	security := strings.ToLower(strings.TrimSpace(q.Get("security")))
	switch security {
	case "tls":
		applyTLS(p, q)
		if err := applyCertChecks(p, q, "vless"); err != nil {
			return nil, err
		}
	case "reality":
		switch network {
		case "tcp", "raw", "grpc", "xhttp", "h2", "http":
		default:
			return nil, fmt.Errorf("vless: reality over %q is not supported", network)
		}
		applyTLS(p, q)
		applyRealityOpts(p, q)
	case "", "none":
	default:
		return nil, fmt.Errorf("vless: security %q is not supported", security)
	}

	switch network {
	case "ws", "httpupgrade":
		ws := map[string]any{}
		if path := q.Get("path"); path != "" {
			ws["path"] = path
		}
		if host := q.Get("host"); host != "" {
			ws["headers"] = map[string]any{"Host": host}
		}
		if network == "httpupgrade" {
			ws["v2ray-http-upgrade"] = true
			p["network"] = "ws"
		}
		p["ws-opts"] = ws
	case "grpc":
		if svc := q.Get("serviceName"); svc != "" {
			p["grpc-opts"] = map[string]any{"grpc-service-name": svc}
		}
	case "xhttp":
		xh := map[string]any{}
		if path := q.Get("path"); path != "" {
			xh["path"] = path
		}
		if host := q.Get("host"); host != "" {
			xh["host"] = host
		}
		if mode := q.Get("mode"); mode != "" {
			xh["mode"] = mode
		}
		p["xhttp-opts"] = xh
	}

	return p, nil
}

func applyRealityOpts(p map[string]any, q url.Values) {
	reality := map[string]any{}
	if pbk := q.Get("pbk"); pbk != "" {
		reality["public-key"] = pbk
	}
	if sid := q.Get("sid"); sid != "" {
		reality["short-id"] = sid
	}
	p["reality-opts"] = reality
}

func applyTLS(p map[string]any, q url.Values) {
	p["tls"] = true
	if sni := q.Get("sni"); sni != "" {
		p["servername"] = sni
	}
	if fp := q.Get("fp"); fp != "" {
		p["client-fingerprint"] = fp
	}
	if alpn := q.Get("alpn"); alpn != "" {
		p["alpn"] = strings.Split(alpn, ",")
	}
}

func trojanProxy(link, name string) (map[string]any, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, logfmt.WithoutURL(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	q := u.Query()
	p := map[string]any{
		"name":     name,
		"type":     "trojan",
		"server":   u.Hostname(),
		"port":     port,
		"password": u.User.Username(),
		"udp":      true,
	}
	if sni := q.Get("sni"); sni != "" {
		p["sni"] = sni
	}
	if fp := q.Get("fp"); fp != "" {
		p["client-fingerprint"] = fp
	}
	if alpn := q.Get("alpn"); alpn != "" {
		p["alpn"] = strings.Split(alpn, ",")
	}
	if err := applyCertChecks(p, q, "trojan"); err != nil {
		return nil, err
	}
	if err := applyTrojanReality(p, q); err != nil {
		return nil, err
	}
	if err := applyTrojanTransport(p, q); err != nil {
		return nil, err
	}
	return p, nil
}

// mihomo's Trojan carries REALITY as reality-opts with the public key and the
// short id. Without a public key mihomo dials plain TLS, and it has no option
// for a spider path, so a link that lacks the key or names one fails.
func applyTrojanReality(p map[string]any, q url.Values) error {
	if strings.ToLower(strings.TrimSpace(q.Get("security"))) != "reality" {
		return nil
	}
	if q.Get("pbk") == "" {
		return fmt.Errorf("trojan: reality needs a public key")
	}
	// mihomo's Trojan dials REALITY only on plain TCP and gRPC; its WebSocket
	// branch dials ordinary TLS.
	switch network := strings.ToLower(strings.TrimSpace(q.Get("type"))); network {
	case "tcp", "raw", "", "grpc":
	default:
		return fmt.Errorf("trojan: reality over %q is not supported", network)
	}
	if q.Get("spx") != "" {
		return fmt.Errorf("trojan: reality spider path is not supported")
	}
	applyRealityOpts(p, q)
	return nil
}

// mihomo's Trojan outbound runs over plain TCP, WebSocket (HTTPUpgrade as its
// option) and gRPC. A transport or HTTP header it lacks fails the link: run as
// plain TCP it would connect to nothing the server speaks.
func applyTrojanTransport(p map[string]any, q url.Values) error {
	network := strings.ToLower(strings.TrimSpace(q.Get("type")))
	switch network {
	case "tcp", "raw", "":
		if header := strings.ToLower(strings.TrimSpace(q.Get("headerType"))); header != "" && header != "none" {
			return fmt.Errorf("trojan: tcp header %q is not supported", header)
		}
	case "ws", "websocket", "httpupgrade":
		p["network"] = "ws"
		opts := map[string]any{}
		if path := q.Get("path"); path != "" {
			opts["path"] = path
		}
		if host := q.Get("host"); host != "" {
			opts["headers"] = map[string]any{"Host": host}
		}
		if network == "httpupgrade" {
			opts["v2ray-http-upgrade"] = true
		}
		p["ws-opts"] = opts
	case "grpc":
		p["network"] = "grpc"
		p["grpc-opts"] = map[string]any{"grpc-service-name": q.Get("serviceName")}
	default:
		return fmt.Errorf("trojan: transport %q is not supported", network)
	}
	return nil
}

func hysteria2Proxy(link, name string) (map[string]any, error) {
	normalized, portSpec, err := normalizeHy2Link(link)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return nil, logfmt.WithoutURL(err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("hysteria2: missing server host")
	}
	port, ports, err := hy2Ports(portSpec)
	if err != nil {
		return nil, err
	}

	password := ""
	if u.User != nil {
		password = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			password = password + ":" + pass
		}
	}

	p := map[string]any{
		"name":     name,
		"type":     "hysteria2",
		"server":   host,
		"password": password,
	}
	if ports != "" {
		// mihomo ignores port when ports is set, but some builds still require port.
		p["ports"] = ports
		p["port"] = port
	} else {
		p["port"] = port
	}

	q := u.Query()
	if sni := q.Get("sni"); sni != "" {
		p["sni"] = sni
	}
	if obfs := q.Get("obfs"); obfs != "" {
		p["obfs"] = obfs
		if op := q.Get("obfs-password"); op != "" {
			p["obfs-password"] = op
		}
	}
	if v := q.Get("obfs-min-packet-size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			p["obfs-min-packet-size"] = n
		}
	}
	if v := q.Get("obfs-max-packet-size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			p["obfs-max-packet-size"] = n
		}
	}
	switch strings.ToLower(q.Get("insecure")) {
	case "1", "true":
		p["skip-cert-verify"] = true
	}
	if pin := q.Get("pinSHA256"); pin != "" {
		p["fingerprint"] = pin
	}
	if alpn := q.Get("alpn"); alpn != "" {
		parts := strings.Split(alpn, ",")
		out := make([]string, 0, len(parts))
		for _, a := range parts {
			if a = strings.TrimSpace(a); a != "" {
				out = append(out, a)
			}
		}
		if len(out) > 0 {
			p["alpn"] = out
		}
	}
	if up := strings.TrimSpace(q.Get("up")); up != "" {
		p["up"] = up
	}
	if down := strings.TrimSpace(q.Get("down")); down != "" {
		p["down"] = down
	}
	if hop := strings.TrimSpace(q.Get("hop-interval")); hop != "" {
		p["hop-interval"] = hop
	}
	return p, nil
}

// url.Parse rejects hopping ports — rewrite to the first port, return the original spec.
func normalizeHy2Link(link string) (normalized, portSpec string, err error) {
	schemeIdx := strings.Index(link, "://")
	if schemeIdx < 0 {
		return "", "", fmt.Errorf("hysteria2: missing scheme")
	}
	prefix := link[:schemeIdx+3]
	rest := link[schemeIdx+3:]

	end := len(rest)
	for _, sep := range []byte{'?', '#', '/'} {
		if i := strings.IndexByte(rest, sep); i >= 0 && i < end {
			end = i
		}
	}
	authority, suffix := rest[:end], rest[end:]

	userinfo, hostport := "", authority
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		userinfo = authority[:at]
		hostport = authority[at+1:]
	}

	host, portSpec := hy2SplitHostPort(hostport)
	if host == "" {
		return "", "", fmt.Errorf("hysteria2: missing server host")
	}
	firstPort := "443"
	if portSpec != "" {
		first := portSpec
		if i := strings.IndexAny(portSpec, ",-"); i >= 0 {
			first = portSpec[:i]
		}
		if first != "" {
			firstPort = first
		}
	} else {
		portSpec = ""
	}

	var b strings.Builder
	b.WriteString(prefix)
	if userinfo != "" {
		b.WriteString(userinfo)
		b.WriteByte('@')
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		b.WriteByte('[')
		b.WriteString(host)
		b.WriteByte(']')
	} else {
		b.WriteString(host)
	}
	b.WriteByte(':')
	b.WriteString(firstPort)
	b.WriteString(suffix)
	return b.String(), portSpec, nil
}

func hy2SplitHostPort(hostport string) (host, portSpec string) {
	if hostport == "" {
		return "", ""
	}
	if strings.HasPrefix(hostport, "[") {
		if i := strings.Index(hostport, "]:"); i >= 0 {
			return hostport[:i+1], hostport[i+2:]
		}
		return hostport, ""
	}
	if i := strings.LastIndex(hostport, ":"); i >= 0 {
		return hostport[:i], hostport[i+1:]
	}
	return hostport, ""
}

// Empty → 443; hopping → ports + first as port.
func hy2Ports(portSpec string) (port int, ports string, err error) {
	portSpec = strings.TrimSpace(portSpec)
	if portSpec == "" {
		return 443, "", nil
	}
	if n, err := strconv.Atoi(portSpec); err == nil {
		if n <= 0 || n > 65535 {
			return 0, "", fmt.Errorf("hysteria2: invalid port %q", portSpec)
		}
		return n, "", nil
	}
	first := portSpec
	if i := strings.IndexAny(portSpec, ",-"); i >= 0 {
		first = portSpec[:i]
	}
	n, err := strconv.Atoi(first)
	if err != nil || n <= 0 || n > 65535 {
		return 0, "", fmt.Errorf("hysteria2: invalid ports %q", portSpec)
	}
	return n, portSpec, nil
}

// AWG over mihomo's wireguard outbound (amnezia-wg-option). Keys stay base64
// (mihomo decodes them); h1-h4 / i1-i5 pass as strings so AWG 2.0 ranges and
// the i1 CPS blob survive verbatim.
func wireguardProxy(link, name string) (map[string]any, error) {
	ini, err := awgconfig.NormalizeToINI(link)
	if err != nil {
		return nil, fmt.Errorf("awg: %w", err)
	}
	sections := parseINI(ini)
	iface, peer := sections["interface"], sections["peer"]

	host, portStr, err := net.SplitHostPort(peer["endpoint"])
	if err != nil {
		return nil, fmt.Errorf("awg endpoint %q: %w", peer["endpoint"], err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("awg endpoint port: %w", err)
	}
	if iface["privatekey"] == "" || peer["publickey"] == "" {
		return nil, fmt.Errorf("awg: missing PrivateKey or PublicKey")
	}

	p := map[string]any{
		"name":        name,
		"type":        "wireguard",
		"server":      host,
		"port":        port,
		"private-key": iface["privatekey"],
		"public-key":  peer["publickey"],
		"udp":         true,
		// mihomo's default here is its own mips stack; gVisor is the one the
		// rest of the core runs and the one this path is tested on.
		"ip-stack": map[string]any{"mode": "gvisor"},
	}
	if v4, v6 := splitWGAddresses(iface["address"]); v4 != "" || v6 != "" {
		if v4 != "" {
			p["ip"] = v4
		}
		if v6 != "" {
			p["ipv6"] = v6
		}
	}
	if psk := peer["presharedkey"]; psk != "" {
		p["pre-shared-key"] = psk
	}
	if allowed := splitCSV(peer["allowedips"]); len(allowed) > 0 {
		p["allowed-ips"] = allowed
	} else {
		p["allowed-ips"] = []string{"0.0.0.0/0", "::/0"}
	}
	if mtu, err := strconv.Atoi(iface["mtu"]); err == nil && mtu > 0 {
		p["mtu"] = mtu
	}
	// mihomo takes one interval; of an AWG 3.x range it gets the shortest,
	// which keeps a NAT mapping alive as well as any value in the range.
	keepalive, _, _ := strings.Cut(peer["persistentkeepalive"], "-")
	if ka, err := strconv.Atoi(strings.TrimSpace(keepalive)); err == nil && ka > 0 {
		p["persistent-keepalive"] = ka
	}

	awgOpt, err := amneziaOption(iface)
	if err != nil {
		return nil, err
	}
	if len(awgOpt) > 0 {
		p["amnezia-wg-option"] = awgOpt
	}

	return p, nil
}

// awgInt reads a whole-number AWG option. A value that is not one fails the
// config: dropping it would weaken the obfuscation unannounced.
func awgInt(iface map[string]string, key string) (int, bool, error) {
	v := iface[key]
	if v == "" {
		return 0, false, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false, fmt.Errorf("awg %s: %q is not a whole number", key, v)
	}
	return n, true, nil
}

// amneziaOption builds mihomo's amnezia-wg-option. A config holding any AWG
// 3.x key runs on mihomo's 3.x device (version 3), which refuses AWG 1.5's
// J1-J3 and Itime; every other config stays on its legacy device.
func amneziaOption(iface map[string]string) (map[string]any, error) {
	opt := map[string]any{}
	for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4"} {
		n, ok, err := awgInt(iface, k)
		if err != nil {
			return nil, err
		}
		if ok {
			opt[k] = n
		}
	}
	// h1-h4 accept AWG 2.0 ranges, i1-i5 carry tag chains.
	for _, k := range []string{"h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5"} {
		if v := iface[k]; v != "" {
			opt[k] = v
		}
	}

	awg3 := false
	for k, uapiName := range awgconfig.AWG3Keys {
		v := iface[k]
		if v == "" {
			continue
		}
		awg3 = true
		name := strings.ReplaceAll(uapiName, "_", "-")
		if _, err := awgconfig.AWG3Value(k, v); err != nil {
			return nil, fmt.Errorf("awg %s: %w", name, err)
		}
		switch k {
		case "headerprotectionkey":
			// mihomo decodes this one as padded standard base64.
			key, _ := awgconfig.KeyBytes(v)
			opt[name] = base64.StdEncoding.EncodeToString(key)
		case "randomtrailers", "disablecookies":
			opt[name], _ = awgconfig.ParseBool(v)
		default:
			opt[name] = v
		}
	}

	if awg3 {
		for _, k := range awgconfig.AWG15Keys {
			if iface[k] != "" {
				return nil, fmt.Errorf("awg: AWG 3.x keys cannot be combined with AWG 1.5's %s", k)
			}
		}
		opt["version"] = 3
		return opt, nil
	}
	for _, k := range awgconfig.AWG15Keys {
		if k == "itime" {
			n, ok, err := awgInt(iface, k)
			if err != nil {
				return nil, err
			}
			if ok {
				opt[k] = n
			}
			continue
		}
		if v := iface[k]; v != "" {
			opt[k] = v
		}
	}
	return opt, nil
}

func parseINI(ini string) map[string]map[string]string {
	out := map[string]map[string]string{}
	section := ""
	for _, raw := range strings.Split(ini, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[] \t"))
			if out[section] == nil {
				out[section] = map[string]string{}
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 || section == "" {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		out[section][key] = strings.TrimSpace(line[eq+1:])
	}
	return out
}

func splitCSV(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if v := strings.TrimSpace(f); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func splitWGAddresses(addr string) (v4, v6 string) {
	for _, a := range splitCSV(addr) {
		ipStr := a
		if slash := strings.IndexByte(ipStr, '/'); slash >= 0 {
			ipStr = ipStr[:slash]
		}
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			if v4 == "" {
				v4 = ipStr
			}
		} else if v6 == "" {
			v6 = ipStr
		}
	}
	return v4, v6
}

// ssProxy parses ss://method:pass@host:port and the base64-userinfo /
// fully-base64 SIP002 variants.
func ssProxy(link, name string) (map[string]any, error) {
	body := strings.TrimPrefix(link, "ss://")
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	if i := strings.IndexByte(body, '?'); i >= 0 {
		body = body[:i]
	}

	// Legacy whole-body base64 -> method:pass@host:port.
	if !strings.Contains(body, "@") {
		if decoded, err := decodeBase64(body); err == nil {
			body = decoded
		}
	}

	at := strings.LastIndex(body, "@")
	if at < 0 {
		return nil, fmt.Errorf("ss: missing @host:port")
	}
	userInfo, hostPort := body[:at], body[at+1:]

	// userInfo is method:pass, or base64(method:pass).
	if !strings.Contains(userInfo, ":") {
		if decoded, err := decodeBase64(userInfo); err == nil {
			userInfo = decoded
		}
	}
	colon := strings.IndexByte(userInfo, ':')
	if colon < 0 {
		return nil, fmt.Errorf("ss: userinfo not method:password")
	}
	method, password := userInfo[:colon], userInfo[colon+1:]

	host, portStr, err := splitHostPort(hostPort)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	return map[string]any{
		"name":     name,
		"type":     "ss",
		"server":   host,
		"port":     port,
		"cipher":   method,
		"password": password,
		"udp":      true,
	}, nil
}

func splitHostPort(hostPort string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(hostPort)
	if err != nil {
		return "", "", fmt.Errorf("ss: missing port in %q", hostPort)
	}
	return host, port, nil
}

func decodeBase64(s string) (string, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("not base64")
}
