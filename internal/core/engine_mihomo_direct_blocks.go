//go:build !no_mihomo

package core

import (
	"context"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
)

// directLookup is the resolver an app sent direct has its names looked up on:
// mihomo's direct resolvers, taken once the session's config is applied.
// Stopping a session replaces mihomo's own variable while flows still arrive,
// so a rule never reads that one.
type directLookup struct {
	mu       sync.RWMutex
	resolver resolver.Resolver
}

var mihomoDirectLookup directLookup

func (l *directLookup) set(r resolver.Resolver) {
	l.mu.Lock()
	l.resolver = r
	l.mu.Unlock()
}

func (l *directLookup) addresses(ctx context.Context, host string) ([]netip.Addr, bool) {
	l.mu.RLock()
	r := l.resolver
	l.mu.RUnlock()
	if r == nil {
		return nil, false
	}
	addresses, err := resolver.LookupIPWithResolver(ctx, host, r)
	return addresses, err == nil && len(addresses) > 0
}

// namedFlowAddressBlock makes an address block meet a flow that arrives as a
// name. mihomo's address rules see the flow's address only, and a name from its
// fake-ip arrives with none. The rule asks the direct resolvers for the name
// and refuses the flow when any address they give is blocked, or when they
// cannot answer: a name that cannot be checked is not dialled, as the DIRECT
// outbound would look it up again at the same resolvers.
type namedFlowAddressBlock struct {
	C.Rule
	lookup *directLookup
}

func (b namedFlowAddressBlock) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if metadata.Host == "" || metadata.DstIP.IsValid() {
		return b.Rule.Match(metadata, helper)
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
	defer cancel()
	addresses, ok := b.lookup.addresses(ctx, metadata.Host)
	if !ok {
		return true, b.Rule.Adapter()
	}
	probe := *metadata
	for _, address := range addresses {
		probe.DstIP = address
		if matched, adapter := b.Rule.Match(&probe, helper); matched {
			return true, adapter
		}
	}
	return false, ""
}

// guardDirectAppAddressBlocks wraps the address blocks in the sub-rule the
// process-direct apps go through, so they meet their named flows too.
func guardDirectAppAddressBlocks(subRules map[string][]C.Rule, lookup *directLookup) {
	rules := subRules[mihomoconfig.DirectFlowsSubRule]
	for i, rule := range rules {
		if rule.Adapter() != "REJECT" {
			continue
		}
		switch rule.RuleType() {
		case C.IPCIDR, C.IPSuffix, C.IPASN, C.GEOIP:
			rules[i] = namedFlowAddressBlock{Rule: rule, lookup: lookup}
		}
	}
}
