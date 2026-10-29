package xrayconfig

import (
	"encoding/json"
	"fmt"
	"slices"
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

// xrayMatcher spells an entry as xray's rule fields read it. The core runs
// routing.Profile.Validate first, so every geo code here is one xray can look
// up.
func xrayMatcher(e routing.Entry) string {
	switch e.Kind {
	case routing.KindGeoSite:
		return "geosite:" + e.Value
	case routing.KindGeoIP:
		return "geoip:" + e.Value
	case routing.KindDomainSuffix:
		return "domain:" + e.Value
	case routing.KindDomainFull:
		return "full:" + e.Value
	case routing.KindDomainRegex:
		return "regexp:" + e.Value
	case routing.KindDomainKeyword, routing.KindIPCIDR, routing.KindProcess:
		return e.Value
	}
	return ""
}

// addMatcher puts the entry in the rule's field for its kind; xray ANDs the
// fields of one rule.
func addMatcher(r *fieldRule, e routing.Entry) bool {
	matcher := xrayMatcher(e)
	switch {
	case matcher == "":
		return false
	case e.Kind == routing.KindProcess:
		r.Process = append(r.Process, matcher)
	case e.ByAddress():
		r.IP = append(r.IP, matcher)
	default:
		r.Domain = append(r.Domain, matcher)
	}
	return true
}

// stepRules emits one field rule per step, in order.
func stepRules(steps []routing.Step, inbounds []string, targetOf func(routing.Step) target) []json.RawMessage {
	var rules []json.RawMessage
	for _, step := range steps {
		r := fieldRule{InboundTag: inbounds}
		matched, also := false, len(step.Also) == 0
		for _, e := range step.Entries {
			matched = addMatcher(&r, e) || matched
		}
		for _, e := range step.Also {
			also = addMatcher(&r, e) || also
		}
		if !matched || !also {
			continue
		}
		targetOf(step).apply(&r)
		rules = append(rules, r.raw())
	}
	return rules
}

// blockSteps is the tier's blocks alone, in the order the tier meets them.
func blockSteps(steps []routing.Step) []routing.Step {
	return slices.DeleteFunc(steps, func(s routing.Step) bool { return s.Target != routing.TargetBlock || len(s.Also) > 0 })
}

func isDirectAddress(e routing.Entry) bool {
	return e.Target == routing.TargetDirect && e.ByAddress()
}

// directFinalRules mirrors the tier's address entries up to its last direct
// one: the outbound resolves a name again, and an address an entry ahead of a
// direct one sends elsewhere must not be dialed direct.
func directFinalRules(entries []routing.Entry) []freedomFinalRule {
	var addresses []routing.Entry
	end := 0
	for _, e := range entries {
		if e.ByAddress() {
			addresses = append(addresses, e)
		}
		if isDirectAddress(e) {
			end = len(addresses)
		}
	}
	var rules []freedomFinalRule
	for _, e := range addresses[:end] {
		action := "block"
		if isDirectAddress(e) {
			action = "allow"
		}
		if n := len(rules); n > 0 && rules[n-1].Action == action {
			rules[n-1].IP = append(rules[n-1].IP, xrayMatcher(e))
			continue
		}
		rules = append(rules, freedomFinalRule{Action: action, IP: []string{xrayMatcher(e)}})
	}
	return rules
}

// anyDomain matches every flow addressed by a name.
const anyDomain = "regexp:."

// anyIP matches every flow addressed by IP, and a name once xray resolves it.
var anyIP = []string{"0.0.0.0/0", "::/0"}

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

	// IPIfNonMatch resolves a name only when no rule matched it, so the app's
	// catch-all, and its rule keeping names off the local networks, must not
	// match a name before it resolves. They wait only where an IP rule could
	// still take the name, since the lookup is a DNS query of its own, sent in
	// the clear under fake-ip. A name that does not resolve matches no rule and
	// takes the first outbound, a proxy. A per-app VPN flow's catch-all
	// matches a name on the first pass, so under IPIfNonMatch its names are
	// never looked up and its blocks by address take a flow addressed by IP.
	var appResolveIP []string
	if strategy, _ := NormalizeDomainStrategy(p.DomainStrategy); strategy == strategyIPIfNonMatch && tiersHoldIPs(p.Tiers) {
		appResolveIP = anyIP
	}

	// Priority (first match wins): protocol kill-switches -> exit echo ->
	// force-proxy flows -> tiers in order, each as its routing.Tier.Steps ->
	// local networks -> mode catch-all. Explicit direct/proxy rules are emitted
	// in both modes; the catch-all decides what unlisted traffic does.
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
			rules = append(rules, stepRules(blockSteps(tier.Steps()), forceInbound, func(routing.Step) target { return block })...)
		}
		if p.LocalNetworks {
			// A name the router resolves into the local networks stays off the
			// LAN rule: the direct outbound would resolve it again and could
			// dial a public address.
			named := fieldRule{InboundTag: forceInbound, Domain: []string{anyDomain}}
			proxy.apply(&named)
			rules = append(rules, named.raw())
			lan := fieldRule{InboundTag: forceInbound, IP: routing.LocalNetworkCIDRs}
			direct.apply(&lan)
			rules = append(rules, lan.raw())
		}
		forceRule := fieldRule{InboundTag: forceInbound}
		proxy.apply(&forceRule)
		rules = append(rules, forceRule.raw())
	}
	for i, tier := range p.Tiers {
		entries := tier.Entries()
		// In direct-all the catch-all sends a name direct anyway, so the IP
		// entries keep the plain direct outbound there.
		directByIP := direct
		if slices.ContainsFunc(entries, isDirectAddress) && p.ResolvedMode() == ModeProxyAll {
			directByIP = target{tag: tierDirectTag(i)}
			ensureOutbound(cfg, directByIP.tag, tierDirectOutbound(p, directByIP.tag, directFinalRules(entries)))
		}
		rules = append(rules, stepRules(tier.Steps(), nil, func(step routing.Step) target {
			switch {
			case step.Target == routing.TargetBlock:
				return block
			case step.Target == routing.TargetProxy:
				return proxy
			case step.Entries[0].ByAddress():
				return directByIP
			}
			return direct
		})...)
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

func tiersHoldIPs(tiers []routing.Tier) bool {
	for _, tier := range tiers {
		if slices.ContainsFunc(tier.Entries(), routing.Entry.ByAddress) {
			return true
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

// tierDirectOutbound dials only an address its rules allow: the router takes
// a name when any of its addresses is in a direct entry, and the outbound
// resolves it again. Its finalRules refuse a name the entries cover in part,
// or a sniffed flow whose own address they miss, here and at once; xray cannot
// move a flow to another outbound once routing has chosen this one, so it is
// not tunnelled.
func tierDirectOutbound(p RoutingProfile, tag string, rules []freedomFinalRule) xrayConf.OutboundDetourConfig {
	ob := directOutbound(p, tag)
	noDelay := 0
	settings, _ := json.Marshal(struct {
		FinalRules []freedomFinalRule `json:"finalRules"`
	}{append(rules, freedomFinalRule{Action: "block", BlockDelay: &noDelay})})
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
