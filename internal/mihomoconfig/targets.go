package mihomoconfig

import (
	"fmt"
	"slices"

	"github.com/metacubex/mihomo/config"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// Generated names for the targets a route names. They are taken after the
// pool's link names and reservedNames, and move aside for either.
const (
	serverNamePrefix = "rt-"
	groupNamePrefix  = "rb-"
	memberNamePrefix = "rg-"
	hopNamePrefix    = "rc-"
)

// freeName is base, or base-2, base-3 and so on when the name is taken.
func freeName(base string, used map[string]bool) string {
	name := base
	for n := 2; used[name]; n++ {
		name = fmt.Sprintf("%s-%d", base, n)
	}
	used[name] = true
	return name
}

// addNamedProxies adds the proxies and groups the tiers' routes name and
// returns the name each id routes to. Only what a route names is built. A
// chain's hop after the first dials through the one before it with
// dialer-proxy, and mihomo's parser refuses a hop whose dialer is missing or
// that closes a cycle. A group balances with the session's strategy.
func addNamedProxies(raw *config.RawConfig, poolNames []string, p routing.Profile, opts Options) (map[string]string, error) {
	var ids []string
	for _, tier := range p.Tiers {
		for _, r := range tier.Routes {
			if !slices.Contains(ids, r.To) {
				ids = append(ids, r.To)
			}
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	used := make(map[string]bool, len(reservedNames)+len(poolNames))
	for _, name := range reservedNames {
		used[name] = true
	}
	for _, name := range poolNames {
		used[name] = true
	}
	addProxy := func(id, name, link string) (map[string]any, error) {
		proxy, err := proxyFromLink(link, name)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", id, err)
		}
		raw.Proxy = append(raw.Proxy, proxy)
		return proxy, nil
	}

	named := map[string]string{}
	for _, id := range ids {
		kind, _ := p.Targets.Kind(id)
		switch kind {
		case routing.KindServerTarget:
			name := freeName(serverNamePrefix+id, used)
			if _, err := addProxy(id, name, p.Targets.Link(id)); err != nil {
				return nil, err
			}
			named[id] = name
		case routing.KindGroupTarget:
			group := p.Targets.Groups[slices.IndexFunc(p.Targets.Groups, func(g routing.TargetGroup) bool { return g.ID == id })]
			var members []string
			for i, server := range group.Servers {
				name := freeName(fmt.Sprintf("%s%s-%d", memberNamePrefix, id, i), used)
				if _, err := addProxy(id, name, p.Targets.Link(server)); err != nil {
					return nil, err
				}
				members = append(members, name)
			}
			name := freeName(groupNamePrefix+id, used)
			g, err := balancerGroup(name, members, opts.Strategy, opts.ProbeURL)
			if err != nil {
				return nil, err
			}
			raw.ProxyGroup = append(raw.ProxyGroup, g)
			named[id] = name
		case routing.KindChainTarget:
			chain := p.Targets.Chains[slices.IndexFunc(p.Targets.Chains, func(c routing.TargetChain) bool { return c.ID == id })]
			previous := ""
			for i, hop := range chain.Hops {
				name := freeName(fmt.Sprintf("%s%s-%d", hopNamePrefix, id, i), used)
				proxy, err := addProxy(id, name, p.Targets.Link(hop))
				if err != nil {
					return nil, err
				}
				if previous != "" {
					proxy["dialer-proxy"] = previous
				}
				previous = name
			}
			named[id] = previous
		default:
			return nil, fmt.Errorf("route names undefined id %q", id)
		}
	}
	return named, nil
}
