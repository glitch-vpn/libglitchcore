//go:build !no_mihomo

package core

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/metacubex/mihomo/dns"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
)

// mihomoProbeDial is the liveness probe's dial. In a pool with a WireGuard or
// AmneziaWG outbound, which finds a name's address itself and may pick IPv6,
// the probe is held to IPv4 until the exit's IPv6 is known to carry
// (ipv4UntilExitCarriesIPv6); any other pool sends the name to the server, which
// picks a family that works.
func (x *CoreController) mihomoProbeDial(links []string, inbound mihomoconfig.Inbound, mark int64) tunnelDialFunc {
	target := mihomoconfig.Target(links)
	dial := x.mihomoTunnelDial(target, mark)
	if !mihomoconfig.ResolvesNamesLocally(links) {
		return dial
	}
	return x.ipv4UntilExitCarriesIPv6(dial, mihomoProbeResolver(target, mihomoconfig.OutboundResolvers(inbound)))
}

// mihomoProbeResolver finds a name's IPv4 address as the WireGuard outbound
// finds it for its own flows: with the session's resolvers, each dialled through
// the pinned target. A query never leaves from the device, whatever the routing
// tiers or the engine's own resolver say.
func mihomoProbeResolver(target string, servers []string) func(ctx context.Context, host string) (netip.Addr, error) {
	var mu sync.Mutex
	var resolver *dns.Resolver
	return func(ctx context.Context, host string) (netip.Addr, error) {
		mu.Lock()
		if resolver == nil {
			pinned, ok := mihomoTunnel.Proxies()[target]
			if !ok {
				mu.Unlock()
				return netip.Addr{}, fmt.Errorf("proxy %s not found", target)
			}
			nameServers, err := dns.ParseNameServer(servers)
			if err != nil {
				mu.Unlock()
				return netip.Addr{}, err
			}
			for i := range nameServers {
				nameServers[i].ProxyAdapter = pinned
			}
			resolver = dns.NewResolver(dns.Config{Main: nameServers}).Resolver
		}
		r := resolver
		mu.Unlock()
		addrs, err := r.LookupIPv4(ctx, host)
		if err != nil {
			return netip.Addr{}, err
		}
		if len(addrs) == 0 {
			return netip.Addr{}, fmt.Errorf("no IPv4 address for %s", host)
		}
		return addrs[0], nil
	}
}
