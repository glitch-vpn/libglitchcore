// Package mihomoconfig builds a mihomo *config.Config from share links (no YAML round-trip).
package mihomoconfig

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	T "github.com/metacubex/mihomo/tunnel"
)

const (
	groupTag = "vpn"
	// Matches the xray observatory default probe URL.
	probeURL = "https://www.gstatic.com/generate_204"

	fakeIPRange = "198.18.0.1/16"

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

// Inbound: loopback mixed, native TUN, or both (TUN path adds mixed for liveness).
type Inbound struct {
	MixedPort int         // > 0 -> loopback socks/http on 127.0.0.1
	Tun       *TunInbound // non-nil -> native TUN inbound
	// Windows bridge: bind outbounds to the physical NIC, not our TUN.
	Interface string
	// Second "forceproxy" listener - always tunnels (process->proxy dialer).
	ForceProxyPort int
	// Bridge-path DNS (native TUN uses TunInbound.DNS). With fake-ip + DNSListenPort,
	// mihomo runs a standalone DNS server the bridge redirects :53 to.
	DNS dnsconfig.Config
	// DNSListenPort > 0 -> mihomo DNS on 127.0.0.1:port.
	DNSListenPort int
	// Auth ("user:pass") for proxy mode ONLY - in bridge mode it would also gate
	// credential-less tun2socks and break the tunnel.
	Auth string
}

const forceProxyListenerName = "forceproxy"

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
	if in.MixedPort <= 0 && in.Tun == nil {
		return nil, fmt.Errorf("no inbound: set MixedPort or Tun")
	}

	raw := config.DefaultRawConfig()
	raw.AllowLan = false
	raw.Mode = T.Rule
	raw.LogLevel = log.WARNING
	if prof.DisableIPv6 {
		// Resolver stops returning AAAA; the ::/0 REJECT (buildRules) kills v6
		// flows that arrive as literals.
		raw.IPv6 = false
	}
	// v2fly .dat from the home dir; the plugin owns updates - no auto-download.
	raw.GeodataMode = true
	raw.GeoAutoUpdate = false
	// The IP->domain mapping lives in the DNS layer, so switching the sniffer
	// off never breaks fake-ip itself.
	raw.Sniffer = config.RawSniffer{
		Enable: !opts.DisableSniffing,
		Sniff: map[string]config.RawSniffingConfig{
			"TLS":  {Ports: []string{"443"}},
			"HTTP": {Ports: []string{"80", "8080-8880"}},
			"QUIC": {Ports: []string{"443"}},
		},
	}

	if in.MixedPort > 0 {
		raw.MixedPort = in.MixedPort // allow-lan:false forces it onto 127.0.0.1
		applyBridgeDNS(raw, in.DNS, in.DNSListenPort)
		if in.Auth != "" {
			raw.Authentication = []string{in.Auth}
		}
	}
	if in.Interface != "" {
		raw.Interface = in.Interface
	}
	if in.Tun != nil {
		applyTun(raw, in.Tun)
	}

	var names []string
	used := map[string]bool{}
	for i, link := range links {
		trimmed := strings.TrimSpace(link)
		if trimmed == "" {
			continue
		}
		name := uniqueName(linkName(trimmed, i), used)
		proxy, err := proxyFromLink(trimmed, name)
		if err != nil {
			return nil, fmt.Errorf("link %d: %w", i, err)
		}
		applyProxyFingerprint(proxy, opts.Fingerprint)
		raw.Proxy = append(raw.Proxy, proxy)
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no links provided")
	}

	target := names[0]
	if len(names) > 1 {
		group, err := balancerGroup(names, opts.Strategy, opts.ProbeURL)
		if err != nil {
			return nil, err
		}
		raw.ProxyGroup = []map[string]any{group}
		target = groupTag
	}

	rules := buildRules(prof, target)
	// Force-proxy inbound: prepend an IN-NAME rule so this listener always wins,
	// sending its traffic to the proxy even in direct-all mode.
	if in.ForceProxyPort > 0 {
		raw.Listeners = append(raw.Listeners, map[string]any{
			"name":   forceProxyListenerName,
			"type":   "mixed",
			"listen": "127.0.0.1",
			"port":   in.ForceProxyPort,
		})
		rules = append([]string{"IN-NAME," + forceProxyListenerName + "," + target}, rules...)
	}
	raw.Rule = rules

	return config.ParseRawConfig(raw)
}

// buildRules translates the routing profile into mihomo rule lines. target is
// where unlisted traffic goes; an empty profile yields just MATCH,target.
// Priority (first match wins): block -> direct -> proxy -> local -> mode catch-all.
func buildRules(p routing.Profile, target string) []string {
	var rules []string
	if p.DisableIPv6 {
		rules = append(rules, "IP-CIDR,::/0,REJECT,no-resolve")
	}
	if p.DisableUDP {
		// :53 stays open so DNS keeps resolving.
		rules = append(rules, "AND,((NETWORK,udp),(NOT,((DST-PORT,53)))),REJECT")
	}
	rules = append(rules, matcherRules(p.Block, "REJECT")...)
	rules = append(rules, matcherRules(p.Direct, "DIRECT")...)
	rules = append(rules, matcherRules(p.Proxy, target)...)
	if p.LocalNetworks {
		for _, cidr := range routing.LocalNetworkCIDRs {
			rules = append(rules, "IP-CIDR,"+cidr+",DIRECT,no-resolve")
		}
	}
	if p.ResolvedMode() == routing.ModeDirectAll {
		rules = append(rules, "MATCH,DIRECT")
	} else {
		rules = append(rules, "MATCH,"+target)
	}
	return rules
}

// matcherRules classifies a flat matcher list (routing.Classify) into mihomo rule
// lines routing each entry to target. Invalid geo codes (non-ASCII) are dropped so
// one mistake can't fail the whole config.
func matcherRules(matchers []string, target string) []string {
	var out []string
	for _, m := range matchers {
		kind, val, ok := routing.Classify(m)
		if !ok {
			continue
		}
		switch kind {
		case routing.KindGeoSite:
			if routing.ValidGeoCode(val) {
				out = append(out, "GEOSITE,"+val+","+target)
			}
		case routing.KindGeoIP:
			if routing.ValidGeoCode(val) {
				out = append(out, "GEOIP,"+val+","+target+",no-resolve")
			}
		case routing.KindDomainSuffix:
			out = append(out, "DOMAIN-SUFFIX,"+val+","+target)
		case routing.KindDomainFull:
			out = append(out, "DOMAIN,"+val+","+target)
		case routing.KindDomainKeyword:
			out = append(out, "DOMAIN-KEYWORD,"+val+","+target)
		case routing.KindDomainRegex:
			out = append(out, "DOMAIN-REGEX,"+val+","+target)
		case routing.KindIPCIDR:
			out = append(out, "IP-CIDR,"+routing.NormalizeCIDR(val)+","+target+",no-resolve")
		case routing.KindProcess:
			out = append(out, "PROCESS-NAME,"+val+","+target)
		}
	}
	return out
}

// Strategies mihomo accepts (besides "" = url-test default); the plugin gates on
// this before calling the core.
var Strategies = []string{"url-test", "fallback", "load-balance", "load-balance-hash"}

func balancerGroup(names []string, strategy, probe string) (map[string]any, error) {
	if strings.TrimSpace(probe) == "" {
		probe = probeURL
	}
	g := map[string]any{
		"name":     groupTag,
		"proxies":  names,
		"url":      probe,
		"interval": 300,
	}
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "", "url-test":
		g["type"] = "url-test"
	case "fallback":
		g["type"] = "fallback"
	case "load-balance", "round-robin":
		g["type"] = "load-balance"
		g["strategy"] = "round-robin"
	case "load-balance-hash", "consistent-hashing":
		g["type"] = "load-balance"
		g["strategy"] = "consistent-hashing"
	default:
		return nil, fmt.Errorf("unknown mihomo balancer strategy %q", strategy)
	}
	return g, nil
}

// Windows bridge DNS (no TUN hijack). v4-only fake IPs - AAAA would leak real v6.
func applyBridgeDNS(raw *config.RawConfig, dns dnsconfig.Config, listenPort int) {
	if !dns.FakeIP() || listenPort <= 0 {
		return
	}
	raw.DNS.Enable = true
	raw.DNS.Listen = fmt.Sprintf("127.0.0.1:%d", listenPort)
	raw.DNS.IPv6 = false
	raw.DNS.EnhancedMode = C.DNSFakeIP
	raw.DNS.FakeIPRange = fakeIPRangeBridge
	if filter := dns.NormalizedFilter(); len(filter) > 0 {
		raw.DNS.FakeIPFilter = filter
	}
	raw.DNS.NameServer = dns.NormalizedServers("1.1.1.1")
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
	if t.DNS.FakeIP() {
		raw.DNS.EnhancedMode = C.DNSFakeIP
		raw.DNS.FakeIPRange = fakeIPRange
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
}

func applyProxyFingerprint(proxy map[string]any, fp string) {
	fp = strings.TrimSpace(fp)
	if fp == "" || !ValidFingerprint(fp) {
		return
	}
	switch proxy["type"] {
	case "vless", "trojan":
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
	case strings.HasPrefix(lower, awgconfig.LinkScheme), strings.Contains(link, "[Interface]"):
		return wireguardProxy(link, name)
	default:
		return nil, fmt.Errorf("unsupported link scheme")
	}
}

func linkName(link string, idx int) string {
	var frag string
	if strings.HasPrefix(strings.ToLower(link), awgconfig.LinkScheme) {
		frag = awgconfig.LinkName(link)
	} else if u, err := url.Parse(link); err == nil {
		frag = u.Fragment // url.Parse already %-decodes
	}
	if frag = sanitizeName(frag); frag != "" {
		return frag
	}
	return fmt.Sprintf("proxy-%d", idx)
}

// Commas would break rule lines; spaces/pipes/emoji are fine as proxy names.
func sanitizeName(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, ",", " "))
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
		return nil, err
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	q := u.Query()
	network := q.Get("type")
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

	switch q.Get("security") {
	case "tls":
		applyTLS(p, q)
	case "reality":
		applyTLS(p, q)
		reality := map[string]any{}
		if pbk := q.Get("pbk"); pbk != "" {
			reality["public-key"] = pbk
		}
		if sid := q.Get("sid"); sid != "" {
			reality["short-id"] = sid
		}
		p["reality-opts"] = reality
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
		return nil, err
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
	if q.Get("allowInsecure") == "1" {
		p["skip-cert-verify"] = true
	}
	return p, nil
}

func hysteria2Proxy(link, name string) (map[string]any, error) {
	normalized, portSpec, err := normalizeHy2Link(link)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return nil, err
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
	if ka, err := strconv.Atoi(peer["persistentkeepalive"]); err == nil && ka > 0 {
		p["persistent-keepalive"] = ka
	}

	awgOpt := map[string]any{}
	for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "itime"} {
		if v, err := strconv.Atoi(iface[k]); err == nil && iface[k] != "" {
			awgOpt[k] = v
		}
	}
	// String params: h1-h4 accept AWG 2.0 ranges, i1-i5/j1-j3 carry blobs.
	for _, k := range []string{"h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3"} {
		if v := iface[k]; v != "" {
			awgOpt[k] = v
		}
	}
	if len(awgOpt) > 0 {
		p["amnezia-wg-option"] = awgOpt
	}

	return p, nil
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
	i := strings.LastIndex(hostPort, ":")
	if i < 0 {
		return "", "", fmt.Errorf("ss: missing port in %q", hostPort)
	}
	return hostPort[:i], hostPort[i+1:], nil
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
