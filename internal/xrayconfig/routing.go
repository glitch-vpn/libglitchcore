package xrayconfig

import (
	"encoding/json"

	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

const (
	directTag = "direct"
	blockTag  = "block"

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

// Invalid geo codes (non-ASCII, e.g. "рф" typed as geoip) are dropped so one
// bad entry can't fail the whole config; "domain:рф" is valid and kept.
func matcherRules(matchers []string, t target) []json.RawMessage {
	var domains, ips, processes []string
	for _, m := range matchers {
		kind, val, ok := routing.Classify(m)
		if !ok {
			continue
		}
		switch kind {
		case routing.KindGeoSite:
			if routing.ValidGeoCode(val) {
				domains = append(domains, "geosite:"+val)
			}
		case routing.KindGeoIP:
			if routing.ValidGeoCode(val) {
				ips = append(ips, "geoip:"+val)
			}
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

// applyRouting is a free function because RoutingProfile aliases a type from
// another package; existing balancers on cfg.RouterConfig are preserved.
func applyRouting(p RoutingProfile, cfg *xrayConf.Config, proxyTag string, targetIsBalancer bool) {
	proxy := target{tag: proxyTag, isBalancer: targetIsBalancer}
	direct := target{tag: directTag}
	block := target{tag: blockTag}

	needDirect := p.ResolvedMode() == ModeDirectAll || p.LocalNetworks || len(p.Direct) > 0
	needBlock := len(p.Block) > 0 || p.DisableIPv6 || p.DisableUDP

	if needDirect {
		ensureDirectOutbound(p, cfg)
	}
	if needBlock {
		ensureOutbound(cfg, blockTag, xrayConf.OutboundDetourConfig{Protocol: "blackhole", Tag: blockTag})
	}

	// Priority (first match wins): protocol kill-switches -> block -> explicit
	// direct -> explicit proxy -> local networks -> mode catch-all. Explicit
	// direct/proxy rules are emitted in both modes; the catch-all decides what
	// unlisted traffic does.
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
	rules = append(rules, matcherRules(p.Block, block)...)
	rules = append(rules, matcherRules(p.Direct, direct)...)
	rules = append(rules, matcherRules(p.Proxy, proxy)...)

	if p.LocalNetworks {
		r := fieldRule{IP: routing.LocalNetworkCIDRs}
		direct.apply(&r)
		rules = append(rules, r.raw())
	}

	// Force-proxy inbound (per-process process->proxy): always tunnels, so
	// "route only this app through the VPN" holds even in direct-all mode.
	if hasProcessProxy(p) {
		forceRule := fieldRule{InboundTag: []string{forceProxyTag}}
		proxy.apply(&forceRule)
		rules = append(rules, forceRule.raw())
	}

	catchAll := fieldRule{InboundTag: []string{"tun2socks"}}
	if p.ResolvedMode() == ModeDirectAll {
		direct.apply(&catchAll)
	} else {
		proxy.apply(&catchAll)
	}
	rules = append(rules, catchAll.raw())

	if cfg.RouterConfig == nil {
		cfg.RouterConfig = &xrayConf.RouterConfig{}
	}
	cfg.RouterConfig.RuleList = rules
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
	settings := json.RawMessage(`{"domainStrategy":"UseIP"}`)
	ob := xrayConf.OutboundDetourConfig{
		Protocol: "freedom",
		Tag:      directTag,
		Settings: &settings,
	}
	if p.DirectSendThrough != "" {
		st := p.DirectSendThrough
		ob.SendThrough = &st
	}
	// Bind direct egress to the physical NIC (IP_UNICAST_IF on Windows) so it
	// leaves the machine instead of looping back into the TUN default route.
	// Source-IP bind (SendThrough) alone does not achieve this on Windows.
	if p.DirectInterface != "" {
		ob.StreamSetting = &xrayConf.StreamConfig{
			SocketSettings: &xrayConf.SocketConfig{Interface: p.DirectInterface},
		}
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
