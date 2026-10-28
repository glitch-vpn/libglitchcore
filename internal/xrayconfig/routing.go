package xrayconfig

import (
	"encoding/json"
	"strings"

	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

const (
	directTag = "direct"
	blockTag  = "block"

	// ExitEchoTag is the inbound the core's exit-address echo dials as, in
	// process and with no listener; its rule sends it to the proxy ahead of
	// the tiers, so no profile can keep it from the exit.
	ExitEchoTag = "exitecho"

	ModeProxyAll  = routing.ModeProxyAll
	ModeDirectAll = routing.ModeDirectAll
)

// RoutingProfile aliases the engine-neutral routing type. The home is
// internal/routing; mihomoconfig consumes the same type (no cross-import).
type RoutingProfile = routing.Profile

type fieldRule struct {
	Type        string   `json:"type"`
	OutboundTag string   `json:"outboundTag,omitempty"`
	BalancerTag string   `json:"balancerTag,omitempty"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	Network     string   `json:"network,omitempty"`
	Process     []string `json:"process,omitempty"`
}

func (r fieldRule) raw() json.RawMessage {
	r.Type = "field"
	b, _ := json.Marshal(r)
	return json.RawMessage(b)
}

type target struct {
	tag        string
	isBalancer bool
}

func (t target) apply(r *fieldRule) {
	if t.isBalancer {
		r.BalancerTag = t.tag
	} else {
		r.OutboundTag = t.tag
	}
}

// The core runs routing.Profile.Validate first, so every geo code here is one
// xray can look up.
func matcherRules(matchers []string, t target) []json.RawMessage {
	var domains, ips, processes []string
	for _, m := range matchers {
		kind, val, ok := routing.Classify(m)
		if !ok {
			continue
		}
		switch kind {
		case routing.KindGeoSite:
			domains = append(domains, "geosite:"+val)
		case routing.KindGeoIP:
			ips = append(ips, "geoip:"+val)
		case routing.KindDomainSuffix:
			domains = append(domains, "domain:"+val)
		case routing.KindDomainFull:
			domains = append(domains, "full:"+val)
		case routing.KindDomainKeyword:
			domains = append(domains, val)
		case routing.KindDomainRegex:
			domains = append(domains, "regexp:"+val)
		case routing.KindIPCIDR:
			ips = append(ips, val)
		case routing.KindProcess:
			processes = append(processes, val)
		}
	}

	var rules []json.RawMessage
	if len(domains) > 0 {
		r := fieldRule{Domain: domains}
		t.apply(&r)
		rules = append(rules, r.raw())
	}
	if len(ips) > 0 {
		r := fieldRule{IP: ips}
		t.apply(&r)
		rules = append(rules, r.raw())
	}
	if len(processes) > 0 {
		r := fieldRule{Process: processes}
		t.apply(&r)
		rules = append(rules, r.raw())
	}
	return rules
}

// anyDomain matches every flow addressed by a name.
const anyDomain = "regexp:."

// applyRouting is a free function because RoutingProfile aliases a type from
// another package; existing balancers on cfg.RouterConfig are preserved.
func applyRouting(p RoutingProfile, cfg *xrayConf.Config, proxyTag string, targetIsBalancer bool) {
	proxy := target{tag: proxyTag, isBalancer: targetIsBalancer}
	direct := target{tag: directTag}
	block := target{tag: blockTag}

	needDirect := p.ResolvedMode() == ModeDirectAll || p.LocalNetworks || p.HasDirect()
	needBlock := p.HasBlock() || p.DisableIPv6 || p.DisableUDP

	if needDirect {
		ensureDirectOutbound(p, cfg)
	}
	if needBlock {
		ensureOutbound(cfg, blockTag, xrayConf.OutboundDetourConfig{Protocol: "blackhole", Tag: blockTag})
	}

	// Priority (first match wins): protocol kill-switches -> exit echo ->
	// force-proxy flows -> tiers in order (block -> direct -> proxy within each) -> local networks
	// -> mode catch-all. Explicit direct/proxy rules are emitted in both modes; the
	// catch-all decides what unlisted traffic does.
	var rules []json.RawMessage
	if p.DisableIPv6 {
		r := fieldRule{IP: []string{"::/0"}}
		block.apply(&r)
		rules = append(rules, r.raw())
	}
	if p.DisableUDP {
		// :53 stays open so DNS (and fake-ip interception, whose :53->dns-out rule
		// is prepended ahead of this one by ApplyDNS) keeps resolving.
		r := fieldRule{Network: "udp", Port: "1-52,54-65535"}
		block.apply(&r)
		rules = append(rules, r.raw())
	}
	echoRule := fieldRule{InboundTag: []string{ExitEchoTag}}
	proxy.apply(&echoRule)
	rules = append(rules, echoRule.raw())
	// Force-proxy flows (ForceProxyTag, per-process process->proxy) meet
	// every tier's block and the local networks, then always tunnel, so "route only this app through
	// the VPN" holds even in direct-all mode.
	if hasProcessProxy(p) {
		// Only those flows see these rules; the tiers below stay as they are
		// for everyone else.
		for _, tier := range p.Tiers {
			for _, raw := range matcherRules(tier.Block, block) {
				var r fieldRule
				_ = json.Unmarshal(raw, &r)
				r.InboundTag = []string{ForceProxyTag}
				rules = append(rules, r.raw())
			}
		}
		if p.LocalNetworks {
			// A name-addressed flow stays off the LAN rule: the router may
			// resolve it to a local address while the direct outbound dials
			// another one.
			named := fieldRule{InboundTag: []string{ForceProxyTag}, Domain: []string{anyDomain}}
			proxy.apply(&named)
			rules = append(rules, named.raw())
			lan := fieldRule{InboundTag: []string{ForceProxyTag}, IP: routing.LocalNetworkCIDRs}
			direct.apply(&lan)
			rules = append(rules, lan.raw())
		}
		forceRule := fieldRule{InboundTag: []string{ForceProxyTag}}
		proxy.apply(&forceRule)
		rules = append(rules, forceRule.raw())
	}
	for _, tier := range p.Tiers {
		rules = append(rules, matcherRules(tier.Block, block)...)
		rules = append(rules, matcherRules(tier.Direct, direct)...)
		rules = append(rules, matcherRules(tier.Proxy, proxy)...)
	}

	catchAll := fieldRule{InboundTag: []string{AppTrafficTag}}
	if p.ResolvedMode() == ModeDirectAll {
		direct.apply(&catchAll)
	} else {
		proxy.apply(&catchAll)
	}

	if p.LocalNetworks {
		// Only a flow addressed by IP goes direct on the LAN rule; a name takes
		// the catch-all outcome it would reach anyway.
		named := fieldRule{InboundTag: []string{AppTrafficTag}, Domain: []string{anyDomain}, OutboundTag: catchAll.OutboundTag, BalancerTag: catchAll.BalancerTag}
		rules = append(rules, named.raw())
		r := fieldRule{IP: routing.LocalNetworkCIDRs}
		direct.apply(&r)
		rules = append(rules, r.raw())
	}
	rules = append(rules, catchAll.raw())

	if cfg.RouterConfig == nil {
		cfg.RouterConfig = &xrayConf.RouterConfig{}
	}
	cfg.RouterConfig.RuleList = rules
	if p.DomainStrategy != "" {
		ds := p.DomainStrategy
		cfg.RouterConfig.DomainStrategy = &ds
	}
}

// NormalizeDomainStrategy maps a caller value onto xray's router strategies
// ("" = leave the engine default, AsIs). Unknown values are reported instead
// of inheriting xray's silent AsIs fallback - a typo would silently disable
// IP-rule matching for domain-form requests.
func NormalizeDomainStrategy(s string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "", true
	case "asis":
		return "AsIs", true
	case "ipifnonmatch":
		return "IPIfNonMatch", true
	case "ipondemand":
		return "IPOnDemand", true
	}
	return "", false
}

func hasProcessProxy(p RoutingProfile) bool {
	for _, target := range routing.ProcessRules(p) {
		if target == routing.TargetProxy {
			return true
		}
	}
	return false
}

func ensureDirectOutbound(p RoutingProfile, cfg *xrayConf.Config) {
	ob := xrayConf.OutboundDetourConfig{
		Protocol: "freedom",
		Tag:      directTag,
		StreamSetting: &xrayConf.StreamConfig{
			SocketSettings: &xrayConf.SocketConfig{DomainStrategy: "UseIP"},
		},
	}
	if p.DirectSendThrough != "" {
		st := p.DirectSendThrough
		ob.SendThrough = &st
	}
	// Bind direct egress to the physical NIC (IP_UNICAST_IF on Windows) so it
	// leaves the machine instead of looping back into the TUN default route.
	// Source-IP bind (SendThrough) alone does not achieve this on Windows.
	if p.DirectInterface != "" {
		ob.StreamSetting.SocketSettings.Interface = p.DirectInterface
	}
	ensureOutbound(cfg, directTag, ob)
}

func ensureOutbound(cfg *xrayConf.Config, tag string, ob xrayConf.OutboundDetourConfig) {
	if hasOutbound(cfg, tag) {
		return
	}
	cfg.OutboundConfigs = append(cfg.OutboundConfigs, ob)
}

func hasOutbound(cfg *xrayConf.Config, tag string) bool {
	for i := range cfg.OutboundConfigs {
		if cfg.OutboundConfigs[i].Tag == tag {
			return true
		}
	}
	return false
}
