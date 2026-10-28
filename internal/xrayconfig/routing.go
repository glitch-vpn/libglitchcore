package xrayconfig

import (
	"encoding/json"
	"fmt"
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

// xray's router domain strategies.
const (
	strategyAsIs         = "AsIs"
	strategyIPIfNonMatch = "IPIfNonMatch"
	strategyIPOnDemand   = "IPOnDemand"
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
func splitMatchers(matchers []string) (domains, ips, processes []string) {
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
	return domains, ips, processes
}

func matcherRules(matchers []string, inbounds []string, outcome, ipOutcome target) []json.RawMessage {
	domains, ips, processes := splitMatchers(matchers)
	var rules []json.RawMessage
	if len(domains) > 0 {
		r := fieldRule{InboundTag: inbounds, Domain: domains}
		outcome.apply(&r)
		rules = append(rules, r.raw())
	}
	if len(ips) > 0 {
		r := fieldRule{InboundTag: inbounds, IP: ips}
		ipOutcome.apply(&r)
		rules = append(rules, r.raw())
	}
	if len(processes) > 0 {
		r := fieldRule{InboundTag: inbounds, Process: processes}
		outcome.apply(&r)
		rules = append(rules, r.raw())
	}
	return rules
}

// anyDomain matches every flow addressed by a name.
const anyDomain = "regexp:."

// anyIP matches every flow addressed by IP, and a name once xray resolves it.
var anyIP = []string{"0.0.0.0/0", "::/0"}

// tierInbounds are every inbound that reaches the tiers: the exit echo and the
// per-app VPN flows are settled ahead of them. Naming them keeps a per-app VPN
// flow addressed by a name off the tiers on the first IPIfNonMatch pass, which
// it must leave unmatched to be resolved.
var tierInbounds = []string{AppTrafficTag, dnsInternalTag}

// applyRouting is a free function because RoutingProfile aliases a type from
// another package; existing balancers on cfg.RouterConfig are preserved.
func applyRouting(p RoutingProfile, cfg *xrayConf.Config, proxyTag string, targetIsBalancer bool) {
	proxy := target{tag: proxyTag, isBalancer: targetIsBalancer}
	direct := target{tag: directTag}
	block := target{tag: blockTag}

	needDirect := p.ResolvedMode() == ModeDirectAll || p.LocalNetworks || p.HasDirect()
	needBlock := p.HasBlock() || p.DisableIPv6 || p.DisableUDP

	if needDirect {
		ensureOutbound(cfg, directTag, directOutbound(p, directTag))
	}
	if needBlock {
		ensureOutbound(cfg, blockTag, xrayConf.OutboundDetourConfig{Protocol: "blackhole", Tag: blockTag})
	}

	// IPIfNonMatch resolves a name only when no rule matched it, so a
	// catch-all, and the rule keeping names off the local networks, must not
	// match a name before it resolves. Each waits only where an IP rule could
	// still take the name, since the lookup is a DNS query of its own, sent in
	// the clear under fake-ip. A name that does not resolve matches no rule and
	// takes the first outbound, a proxy.
	var appResolveIP, forceResolveIP []string
	if strategy, _ := NormalizeDomainStrategy(p.DomainStrategy); strategy == strategyIPIfNonMatch {
		if tiersHoldIPs(p.Tiers, func(t routing.Tier) [][]string { return [][]string{t.Block, t.Direct, t.Proxy} }) {
			appResolveIP = anyIP
		}
		if tiersHoldIPs(p.Tiers, func(t routing.Tier) [][]string { return [][]string{t.Block} }) {
			forceResolveIP = anyIP
		}
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
		forceInbound := []string{ForceProxyTag}
		for _, tier := range p.Tiers {
			rules = append(rules, matcherRules(tier.Block, forceInbound, block, block)...)
		}
		if p.LocalNetworks {
			// A name the router resolves into the local networks stays off the
			// LAN rule: the direct outbound would resolve it again and could
			// dial a public address.
			named := fieldRule{InboundTag: forceInbound, Domain: []string{anyDomain}, IP: localNetworksOnceResolved(forceResolveIP)}
			proxy.apply(&named)
			rules = append(rules, named.raw())
			lan := fieldRule{InboundTag: forceInbound, IP: routing.LocalNetworkCIDRs}
			direct.apply(&lan)
			rules = append(rules, lan.raw())
		}
		forceRule := fieldRule{InboundTag: forceInbound, IP: forceResolveIP}
		proxy.apply(&forceRule)
		rules = append(rules, forceRule.raw())
	}
	for i, tier := range p.Tiers {
		rules = append(rules, matcherRules(tier.Block, tierInbounds, block, block)...)
		directByIP := direct
		if _, ips, _ := splitMatchers(tier.Direct); len(ips) > 0 {
			directByIP = target{tag: tierDirectTag(i)}
			ensureOutbound(cfg, directByIP.tag, tierDirectOutbound(p, directByIP.tag, ips))
		}
		rules = append(rules, matcherRules(tier.Direct, tierInbounds, direct, directByIP)...)
		rules = append(rules, matcherRules(tier.Proxy, tierInbounds, proxy, proxy)...)
	}

	appInbound := []string{AppTrafficTag}
	modeOutcome := proxy
	if p.ResolvedMode() == ModeDirectAll {
		modeOutcome = direct
	}
	if p.LocalNetworks {
		// Only a flow addressed by IP goes direct on the LAN rule; a name takes
		// the catch-all outcome it would reach anyway.
		named := fieldRule{InboundTag: appInbound, Domain: []string{anyDomain}, IP: localNetworksOnceResolved(appResolveIP)}
		modeOutcome.apply(&named)
		rules = append(rules, named.raw())
		r := fieldRule{IP: routing.LocalNetworkCIDRs}
		direct.apply(&r)
		rules = append(rules, r.raw())
	}
	catchAll := fieldRule{InboundTag: appInbound, IP: appResolveIP}
	modeOutcome.apply(&catchAll)
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

// localNetworksOnceResolved narrows the rule keeping names off the local
// networks to names resolved into them when the catch-all waits for names to
// resolve; otherwise the rule takes every name, without a lookup.
func localNetworksOnceResolved(resolveIP []string) []string {
	if resolveIP == nil {
		return nil
	}
	return routing.LocalNetworkCIDRs
}

func tiersHoldIPs(tiers []routing.Tier, lists func(routing.Tier) [][]string) bool {
	for _, tier := range tiers {
		for _, list := range lists(tier) {
			if _, ips, _ := splitMatchers(list); len(ips) > 0 {
				return true
			}
		}
	}
	return false
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
		return strategyAsIs, true
	case "ipifnonmatch":
		return strategyIPIfNonMatch, true
	case "ipondemand":
		return strategyIPOnDemand, true
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

func directOutbound(p RoutingProfile, tag string) xrayConf.OutboundDetourConfig {
	ob := xrayConf.OutboundDetourConfig{
		Protocol: "freedom",
		Tag:      tag,
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
	return ob
}

func tierDirectTag(tierIndex int) string {
	return fmt.Sprintf("%s-%d", directTag, tierIndex)
}

type freedomFinalRule struct {
	Action     string   `json:"action"`
	IP         []string `json:"ip,omitempty"`
	BlockDelay *int     `json:"blockDelay,omitempty"`
}

// tierDirectOutbound dials only an address ips hold: the router takes a name
// when any of its addresses is in them, and the outbound resolves it again.
// Its finalRules refuse a name ips cover in part, or a sniffed flow whose own
// address they miss, here and at once; xray cannot move a flow to another
// outbound once routing has chosen this one, so it is not tunnelled.
func tierDirectOutbound(p RoutingProfile, tag string, ips []string) xrayConf.OutboundDetourConfig {
	ob := directOutbound(p, tag)
	noDelay := 0
	settings, _ := json.Marshal(struct {
		FinalRules []freedomFinalRule `json:"finalRules"`
	}{[]freedomFinalRule{
		{Action: "allow", IP: ips},
		{Action: "block", BlockDelay: &noDelay},
	}})
	raw := json.RawMessage(settings)
	ob.Settings = &raw
	return ob
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
