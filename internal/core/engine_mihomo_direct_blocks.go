//go:build !no_mihomo

package core

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/resolver"
	mihomoCfg "github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"

	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// directLookup is the resolver an app sent direct has its names looked up on:
// mihomo's direct resolvers, taken once the session's config is applied.
// Stopping a session replaces mihomo's own variable while flows still arrive,
// so the guarded outbound never reads that one.
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

// directCheckedAdapter names the outbound that dials a process-direct app's
// flows once the address blocks have met the addresses it dials.
const directCheckedAdapter = "DIRECT-CHECKED"

var errDirectFlowRefused = errors.New("direct flow refused: an address of its name is blocked or unchecked")

// applyMihomoConfig starts mihomo on cfg. On the native TUN with the process
// rules leading and an address block in the profile, a process-direct app's
// flows meet the address blocks at the addresses they dial.
func applyMihomoConfig(cfg *mihomoCfg.Config, inbound mihomoconfig.Inbound, bridged bool, prof routing.Profile) {
	guard := !bridged && inbound.Tun != nil && inbound.Tun.ProcessFirst && prof.HasAddressBlock()
	if guard {
		guardDirectAppAddressBlocks(cfg, &mihomoDirectLookup)
	}
	// ApplyConfig is void but blocks through TUN creation.
	executor.ApplyConfig(cfg, true)
	if guard {
		mihomoDirectLookup.set(resolver.DirectHostResolver)
	}
}

// directAppAddressBlocks dials the flows of a process-direct app. mihomo's
// address rules see a flow's address only, and the name from its fake-ip
// arrives with none, so a rule cannot check the address DIRECT then dials: a
// second lookup of the name can answer differently. This outbound looks the
// name up once, refuses the flow when the direct resolvers cannot answer or
// any address they give is blocked, and dials those addresses and no other.
type directAppAddressBlocks struct {
	C.ProxyAdapter
	blocks []C.Rule
	lookup *directLookup
}

// checkedAddresses are the addresses the flow may dial, all of which the
// blocks passed.
func (d *directAppAddressBlocks) checkedAddresses(ctx context.Context, metadata *C.Metadata) ([]netip.Addr, error) {
	var addresses []netip.Addr
	switch {
	case metadata.DstIP.IsValid():
		addresses = []netip.Addr{metadata.DstIP}
	case metadata.Host != "":
		var ok bool
		if addresses, ok = d.lookup.addresses(ctx, metadata.Host); !ok {
			return nil, errDirectFlowRefused
		}
	default:
		return nil, errDirectFlowRefused
	}
	probe := *metadata
	for _, address := range addresses {
		probe.DstIP = address
		for _, block := range d.blocks {
			if matched, _ := block.Match(&probe, C.RuleMatchHelper{ResolveIP: func() {}, FindProcess: func() {}}); matched {
				return nil, errDirectFlowRefused
			}
		}
	}
	return addresses, nil
}

func (d *directAppAddressBlocks) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	addresses, err := d.checkedAddresses(ctx, metadata)
	if err != nil {
		return nil, err
	}
	var dialErr error
	for _, address := range addresses {
		target := *metadata
		target.Host, target.DstIP = "", address
		conn, err := d.ProxyAdapter.DialContext(ctx, &target)
		if err == nil {
			return conn, nil
		}
		dialErr = err
	}
	return nil, dialErr
}

func (d *directAppAddressBlocks) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	addresses, err := d.checkedAddresses(ctx, metadata)
	if err != nil {
		return nil, err
	}
	// The tunnel sends to the address the metadata ends up with.
	metadata.DstIP = addresses[0]
	return d.ProxyAdapter.ListenPacketContext(ctx, metadata)
}

// directFlowEnd is the sub-rule's last rule, sending the flow to the checked
// outbound.
type directFlowEnd struct{ C.Rule }

func (directFlowEnd) Match(*C.Metadata, C.RuleMatchHelper) (bool, string) {
	return true, directCheckedAdapter
}

func (directFlowEnd) Adapter() string { return directCheckedAdapter }

// guardDirectAppAddressBlocks takes the address blocks out of the sub-rule the
// process-direct apps go through and gives their flows to an outbound that
// checks them at the addresses it dials.
func guardDirectAppAddressBlocks(cfg *mihomoCfg.Config, lookup *directLookup) {
	rules := cfg.SubRules[mihomoconfig.DirectFlowsSubRule]
	var kept, blocks []C.Rule
	for _, rule := range rules {
		switch {
		case rule.RuleType() == C.MATCH:
			kept = append(kept, directFlowEnd{rule})
		case rule.Adapter() == "REJECT" && isAddressRule(rule.RuleType()):
			blocks = append(blocks, rule)
		default:
			kept = append(kept, rule)
		}
	}
	direct, ok := cfg.Proxies["DIRECT"]
	if !ok {
		return
	}
	cfg.SubRules[mihomoconfig.DirectFlowsSubRule] = kept
	cfg.Proxies[directCheckedAdapter] = adapter.NewProxy(&directAppAddressBlocks{ProxyAdapter: direct, blocks: blocks, lookup: lookup})
}

func isAddressRule(t C.RuleType) bool {
	switch t {
	case C.IPCIDR, C.IPSuffix, C.IPASN, C.GEOIP:
		return true
	}
	return false
}
