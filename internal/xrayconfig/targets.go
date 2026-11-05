package xrayconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"

	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/proxylink"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/vmesslink"
)

// Named targets keep clear of the pool's "proxy-" selector prefix. Ids are
// [a-z0-9], so a group's "rg-<id>-" prefix never selects another group's
// members.
const (
	serverTagPrefix     = "rt-"
	groupBalancerPrefix = "rb-"
	groupMemberPrefix   = "rg-"
	chainHopTagPrefix   = "rc-"
)

func groupMemberSelector(id string) string {
	return groupMemberPrefix + id + "-"
}

// routeIDs is the ids the tiers' routes name, first use first.
func routeIDs(tiers []routing.Tier) []string {
	var ids []string
	for _, tier := range tiers {
		for _, r := range tier.Routes {
			if !slices.Contains(ids, r.To) {
				ids = append(ids, r.To)
			}
		}
	}
	return ids
}

// chainableOnXray: xray's dialerProxy takes outbound handlers that dial over a
// stream, which only these four protocols' outbounds are here.
func chainableOnXray(link string) (protocol string, ok bool) {
	if vmesslink.IsLink(link) {
		return "vmess", true
	}
	if proxylink.IsLink(link) {
		return string(proxylink.Protocol(link)), false
	}
	u, err := url.Parse(link)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	return scheme, slices.Contains([]string{"vless", "ss", "trojan"}, scheme)
}

// addNamed builds the outbounds, balancers and probes the tiers' routes name
// and returns where each id routes to. Only what a route names is built, so
// an unused target costs no lookup. The pool stays xray's first outbound.
func (res *BuildResult) addNamed(cfg *xrayConf.Config, p RoutingProfile, opts BalancerOptions) (map[string]target, error) {
	res.TrafficTags = slices.Clone(res.OutboundTags)
	ids := routeIDs(p.Tiers)
	if len(ids) == 0 {
		return nil, nil
	}
	named := map[string]target{}
	var groupSelectors []string

	// An outbound the client dials itself resolves its host and is pinned off
	// the tunnel; a later hop of a chain keeps its name for the hop before.
	dial := func(id, tag, link string, direct bool) (*xrayConf.OutboundDetourConfig, error) {
		resolve := keepHost
		if direct {
			resolve = preResolveIPv4
		}
		ob, _, dialIP, err := outboundFromLink(link, tag, resolve)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", id, err)
		}
		if direct && dialIP != "" {
			res.DialIPv4s = append(res.DialIPv4s, dialIP)
		}
		return ob, nil
	}

	for _, id := range ids {
		kind, _ := p.Targets.Kind(id)
		switch kind {
		case routing.KindServerTarget:
			tag := serverTagPrefix + id
			ob, err := dial(id, tag, p.Targets.Link(id), true)
			if err != nil {
				return nil, err
			}
			cfg.OutboundConfigs = append(cfg.OutboundConfigs, *ob)
			res.TrafficTags = append(res.TrafficTags, tag)
			named[id] = target{tag: tag}
		case routing.KindGroupTarget:
			group := p.Targets.Groups[slices.IndexFunc(p.Targets.Groups, func(g routing.TargetGroup) bool { return g.ID == id })]
			o, err := opts.normalized()
			if err != nil {
				return nil, err
			}
			for i, member := range group.Servers {
				tag := fmt.Sprintf("%s%d", groupMemberSelector(id), i)
				ob, err := dial(id, tag, p.Targets.Link(member), true)
				if err != nil {
					return nil, err
				}
				cfg.OutboundConfigs = append(cfg.OutboundConfigs, *ob)
				res.TrafficTags = append(res.TrafficTags, tag)
			}
			balancer := groupBalancerPrefix + id
			if cfg.RouterConfig == nil {
				cfg.RouterConfig = &xrayConf.RouterConfig{}
			}
			cfg.RouterConfig.Balancers = append(cfg.RouterConfig.Balancers, &xrayConf.BalancingRule{
				Tag:         balancer,
				Selectors:   xrayConf.StringList{groupMemberSelector(id)},
				Strategy:    xrayConf.StrategyConfig{Type: o.Strategy},
				FallbackTag: groupMemberSelector(id) + "0",
			})
			groupSelectors = append(groupSelectors, groupMemberSelector(id))
			if cfg.Observatory == nil {
				cfg.Observatory = &xrayConf.ObservatoryConfig{
					ProbeURL:          o.ProbeURL,
					ProbeInterval:     duration.Duration(time.Duration(o.ProbeIntervalSec) * time.Second),
					EnableConcurrency: true,
				}
			}
			named[id] = target{tag: balancer, isBalancer: true}
		case routing.KindChainTarget:
			chain := p.Targets.Chains[slices.IndexFunc(p.Targets.Chains, func(c routing.TargetChain) bool { return c.ID == id })]
			previous := ""
			for i, hop := range chain.Hops {
				link := p.Targets.Link(hop)
				if protocol, ok := chainableOnXray(link); !ok {
					return nil, fmt.Errorf("target %q: xray chains vless, vmess, ss and trojan servers, not %s", id, protocol)
				}
				tag := fmt.Sprintf("%s%s-%d", chainHopTagPrefix, id, i)
				ob, err := dial(id, tag, link, i == 0)
				if err != nil {
					return nil, err
				}
				if i > 0 {
					if err := setDialerProxy(ob, previous); err != nil {
						return nil, fmt.Errorf("target %q: hop %d: %w", id, i+1, err)
					}
				} else {
					res.TrafficTags = append(res.TrafficTags, tag)
				}
				cfg.OutboundConfigs = append(cfg.OutboundConfigs, *ob)
				previous = tag
			}
			named[id] = target{tag: previous}
		default:
			return nil, fmt.Errorf("route names undefined id %q", id)
		}
	}
	if cfg.Observatory != nil {
		cfg.Observatory.SubjectSelector = append(cfg.Observatory.SubjectSelector, groupSelectors...)
	}
	return named, nil
}

var errEchLookup = errors.New("a hop after the first cannot query for its ECH config, which would leave outside the hop before it; give the config list in the link")

// echQueries: xray reads an ECH config list that holds "://" as where to query
// one, with a socket of its own.
func echQueries(list string) bool { return strings.Contains(list, "://") }

// setDialerProxy makes the outbound dial through the one tagged via, the
// download leg of an xhttp hop included: it is a connection of its own with its
// own socket options. It refuses a hop that would look an ECH config up itself,
// on either leg.
func setDialerProxy(ob *xrayConf.OutboundDetourConfig, via string) error {
	if ob.StreamSetting == nil {
		ob.StreamSetting = &xrayConf.StreamConfig{}
	}
	stream := ob.StreamSetting
	if stream.TLSSettings != nil && echQueries(stream.TLSSettings.ECHConfigList) {
		return errEchLookup
	}
	if stream.SocketSettings == nil {
		stream.SocketSettings = &xrayConf.SocketConfig{}
	}
	// DialSystem resolves a domain by these strategies before it reaches the
	// dialer proxy, so a hop after the first keeps neither.
	stream.SocketSettings.DomainStrategy = ""
	stream.SocketSettings.AddressPortStrategy = ""
	stream.SocketSettings.DialerProxy = via
	if stream.XHTTPSettings != nil && len(stream.XHTTPSettings.Extra) > 0 {
		extra, err := dialDownloadThrough(stream.XHTTPSettings.Extra, via)
		if err != nil {
			return err
		}
		stream.XHTTPSettings.Extra = extra
	}
	return nil
}

// dialDownloadThrough sets sockopt.dialerProxy on the download leg an xhttp
// hop's extra carries.
func dialDownloadThrough(extra json.RawMessage, via string) (json.RawMessage, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(extra, &doc); err != nil {
		return nil, fmt.Errorf("xhttp extra: %w", err)
	}
	rawDownload, ok := doc["downloadSettings"]
	if !ok {
		return extra, nil
	}
	var download map[string]json.RawMessage
	if err := json.Unmarshal(rawDownload, &download); err != nil {
		return nil, fmt.Errorf("xhttp downloadSettings: %w", err)
	}
	if tls, ok := download["tlsSettings"]; ok {
		var settings struct {
			ECHConfigList string `json:"echConfigList"`
		}
		if json.Unmarshal(tls, &settings) == nil && echQueries(settings.ECHConfigList) {
			return nil, errEchLookup
		}
	}
	sockopt := map[string]json.RawMessage{}
	if raw, ok := download["sockopt"]; ok {
		if err := json.Unmarshal(raw, &sockopt); err != nil {
			return nil, fmt.Errorf("xhttp downloadSettings sockopt: %w", err)
		}
	}
	delete(sockopt, "domainStrategy")
	delete(sockopt, "addressPortStrategy")
	sockopt["dialerProxy"], _ = json.Marshal(via)
	download["sockopt"], _ = json.Marshal(sockopt)
	doc["downloadSettings"], _ = json.Marshal(download)
	return json.Marshal(doc)
}
