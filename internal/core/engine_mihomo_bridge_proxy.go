//go:build !no_mihomo && !no_xray

package core

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"
)

var _ t2sproxy.Proxy = (*mihomoBridgeProxy)(nil)

// mihomoBridgeProxy hands tun2socks's flows to mihomo's tunnel in process, as
// a TUN inbound would, and the apps' :53 to mihomo's resolver. Once its
// session has ended it refuses every flow.
type mihomoBridgeProxy struct {
	x      *CoreController
	mark   int64
	inName string // the IN-NAME rule's name for force-proxy or force-direct flows, else ""
	// directBlocks is the force-direct flows' sub-rule, held when a block is
	// by address. mihomo checks such a block against one address, found
	// through its general resolver, which travels through the proxy and may
	// not answer, while DIRECT dials by name through the direct resolvers and
	// tries every address they give. The bridge checks the blocks itself: the
	// name, then every address the direct resolvers answer, and a flow one of
	// them refuses, or one they cannot answer, is refused here.
	directBlocks []C.Rule
}

// destination is what mihomo is handed for a flow to dst: dst, or, with the
// blocks checked here and dst standing for a name, the name and the address
// the flow is dialed at.
func (p *mihomoBridgeProxy) destination(ctx context.Context, dst netip.Addr) (host string, ip netip.Addr, err error) {
	if p.directBlocks == nil {
		return "", dst, nil
	}
	host, ok := resolver.FindHostByIP(dst)
	if !ok {
		if resolver.IsFakeIP(dst) {
			return "", netip.Addr{}, fmt.Errorf("fake DNS record %s missing", dst)
		}
		return "", dst, nil
	}
	ctx, cancel := context.WithTimeout(ctx, resolver.DefaultDNSTimeout)
	defer cancel()
	addresses, err := p.directAddresses(ctx, host)
	if err != nil {
		return "", netip.Addr{}, err
	}
	return host, addresses[0], nil
}

// directAddresses walks the blocks in order: a name rule against host, an
// address rule against every address the direct resolvers answer for it,
// resolved at the first such rule. It returns the addresses when no rule
// refuses the flow.
func (p *mihomoBridgeProxy) directAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	var addresses []netip.Addr
	resolved := false
	resolve := func() error {
		if resolved {
			return nil
		}
		resolved = true
		var err error
		addresses, err = resolver.LookupIPWithResolver(ctx, host, resolver.DirectHostResolver)
		if err != nil {
			return fmt.Errorf("resolve %s direct: %w", host, err)
		}
		if len(addresses) == 0 {
			return fmt.Errorf("resolve %s direct: %w", host, resolver.ErrIPNotFound)
		}
		return nil
	}
	metadata := &C.Metadata{Host: host}
	for _, rule := range p.directBlocks {
		if rule.Adapter() != "REJECT" {
			continue
		}
		switch rule.RuleType() {
		case C.IPCIDR, C.IPSuffix, C.IPASN, C.GEOIP:
			if err := resolve(); err != nil {
				return nil, err
			}
			for _, address := range addresses {
				metadata.DstIP = address
				if matched, _ := rule.Match(metadata, C.RuleMatchHelper{}); matched {
					return nil, fmt.Errorf("blocked %s at %s", host, address)
				}
			}
			metadata.DstIP = netip.Addr{}
		default:
			if matched, _ := rule.Match(metadata, C.RuleMatchHelper{}); matched {
				return nil, fmt.Errorf("blocked %s", host)
			}
		}
	}
	if err := resolve(); err != nil {
		return nil, err
	}
	return addresses, nil
}

func (p *mihomoBridgeProxy) DialContext(ctx context.Context, m *M.Metadata) (net.Conn, error) {
	if p.x.sessionGen.Load() != p.mark {
		return nil, errSessionEnded
	}
	if m.DstPort == 53 {
		local, engine := bridgePipe()
		go func() { _ = resolver.RelayDnsConn(context.Background(), engine, resolver.DefaultDnsReadTimeout) }()
		return local, nil
	}
	host, dstIP, err := p.destination(ctx, m.DstIP)
	if err != nil {
		return nil, err
	}
	// A lookup may have waited through the session's end.
	if p.x.sessionGen.Load() != p.mark {
		return nil, errSessionEnded
	}
	local, engine := bridgePipe()
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.TUN,
		InName:  p.inName,
		SrcIP:   m.SrcIP,
		SrcPort: m.SrcPort,
		Host:    host,
		DstIP:   dstIP,
		DstPort: m.DstPort,
	}
	if host != "" {
		// What mihomo sets for a name its resolver mapped: DIRECT then dials
		// a UDP flow at the address checked, not at one it resolves again.
		metadata.DNSMode = C.DNSMapping
	}
	go mihomoTunnel.Tunnel.HandleTCPConn(engine, metadata)
	return local, nil
}

var mihomoBridgeFlowID atomic.Uint64

func (p *mihomoBridgeProxy) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	if p.x.sessionGen.Load() != p.mark {
		return nil, errSessionEnded
	}
	dst := m.DestinationAddrPort()
	var flow *bridgeFlowConn
	if m.DstPort == 53 {
		flow = newBridgeFlowConn(dst, dst, func(query []byte) error {
			if p.x.sessionGen.Load() != p.mark {
				return errSessionEnded
			}
			query = append([]byte(nil), query...)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDnsRelayTimeout)
				defer cancel()
				if answer, err := resolver.RelayDnsPacket(ctx, query, make([]byte, resolver.SafeDnsPacketSize)); err == nil {
					_ = flow.deliver(answer)
				}
			}()
			return nil
		}, nil)
		return flow, nil
	}
	host, dstIP, err := p.destination(context.Background(), dst.Addr())
	if err != nil {
		return nil, err
	}
	dialed := netip.AddrPortFrom(dstIP, dst.Port())
	// mihomo keys its UDP NAT on the source address's text, and tun2socks
	// hands over one flow per destination: a per-flow key keeps two flows
	// from one app port apart, while the address underneath stays the app's.
	src := N.NewCustomAddr(C.TUN.String(), fmt.Sprintf("bridge-%d", mihomoBridgeFlowID.Add(1)),
		net.UDPAddrFromAddrPort(m.SourceAddrPort()))
	target := socks5.ParseAddrToSocksAddr(net.UDPAddrFromAddrPort(dialed))
	// Each datagram is matched anew once its NAT entry lapses, and mihomo's
	// tunnel outlives the session with only DIRECT left.
	flow = newBridgeFlowConn(dst, dialed, func(b []byte) error {
		if p.x.sessionGen.Load() != p.mark {
			return errSessionEnded
		}
		data := pool.Get(len(b))
		copy(data, b)
		packet, metadata := inbound.NewPacket(target, &mihomoBridgePacket{flow: flow, src: src, data: data}, C.TUN, inbound.WithInName(p.inName))
		if host != "" {
			metadata.Host = host
			metadata.DNSMode = C.DNSMapping
		}
		mihomoTunnel.Tunnel.HandleUDPPacket(packet, metadata)
		return nil
	}, nil)
	return flow, nil
}

type mihomoBridgePacket struct {
	flow *bridgeFlowConn
	src  net.Addr
	data []byte
}

func (p *mihomoBridgePacket) Data() []byte { return p.data }

func (p *mihomoBridgePacket) WriteBack(b []byte, from net.Addr) (int, error) {
	var sender netip.AddrPort
	if a, ok := from.(interface{ AddrPort() netip.AddrPort }); ok {
		sender = a.AddrPort()
	}
	if err := p.flow.deliverFrom(b, sender); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *mihomoBridgePacket) Drop() {
	_ = pool.Put(p.data)
	p.data = nil
}

func (p *mihomoBridgePacket) LocalAddr() net.Addr { return p.src }
