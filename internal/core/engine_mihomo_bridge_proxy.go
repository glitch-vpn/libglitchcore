//go:build !no_mihomo && !no_xray && with_tun2socks

package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"
)

var _ t2sproxy.Proxy = (*mihomoBridgeProxy)(nil)

// A refused flow's error reaches the log: none of these names what the app
// was reaching for.
var (
	errDirectNameBlocked    = errors.New("direct app: name blocked")
	errDirectAddressBlocked = errors.New("direct app: address blocked")
	errDirectNameUnresolved = errors.New("direct app: name unresolved")
	errFakeRecordMissing    = errors.New("fake DNS record missing")
)

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
	// hostMapper and directResolver are mihomo's, taken once its session was
	// applied: stopping the session replaces both while flows still arrive,
	// and a read of the package's variables could meet that write.
	hostMapper     resolver.Enhancer
	directResolver resolver.Resolver
	// direct is mihomo's DIRECT outbound, dialing the checked addresses of a
	// named flow here, with the dialer options (interface, protect) it holds.
	direct C.Proxy
}

// destination is what the flow is dialed at: dst, or, with the blocks checked
// here and dst standing for a name, the name and every address that passed
// them, in the order the direct resolvers gave them.
func (p *mihomoBridgeProxy) destination(ctx context.Context, dst netip.Addr) (host string, ips []netip.Addr, err error) {
	if p.directBlocks == nil {
		return "", []netip.Addr{dst}, nil
	}
	if p.hostMapper == nil {
		return "", []netip.Addr{dst}, nil
	}
	host, ok := p.hostMapper.FindHostByIP(dst)
	if !ok {
		if p.hostMapper.IsFakeIP(dst) {
			return "", nil, errFakeRecordMissing
		}
		return "", []netip.Addr{dst}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, resolver.DefaultDNSTimeout)
	defer cancel()
	addresses, err := p.directAddresses(ctx, host)
	if err != nil {
		return "", nil, err
	}
	return host, addresses, nil
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
		if p.directResolver != nil {
			addresses, err = resolver.LookupIPWithResolver(ctx, host, p.directResolver)
		}
		if p.directResolver == nil || err != nil || len(addresses) == 0 {
			// The resolver's own error may quote the name.
			return errDirectNameUnresolved
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
					return nil, errDirectAddressBlocked
				}
			}
			metadata.DstIP = netip.Addr{}
		default:
			if matched, _ := rule.Match(metadata, C.RuleMatchHelper{}); matched {
				return nil, errDirectNameBlocked
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
	host, addresses, err := p.destination(ctx, m.DstIP)
	if err != nil {
		return nil, err
	}
	// A lookup may have waited through the session's end.
	if p.x.sessionGen.Load() != p.mark {
		return nil, errSessionEnded
	}
	if host != "" {
		return p.dialChecked(ctx, m, host, addresses)
	}
	local, engine := bridgePipe()
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.TUN,
		InName:  p.inName,
		SrcIP:   m.SrcIP,
		SrcPort: m.SrcPort,
		DstIP:   addresses[0],
		DstPort: m.DstPort,
	}
	go mihomoTunnel.Tunnel.HandleTCPConn(engine, metadata)
	return local, nil
}

// dialChecked dials a named flow at the addresses that passed the blocks, one
// after another until one answers, through DIRECT itself: handed to mihomo's
// tunnel, a name is looked up again and an address is mapped back to one.
func (p *mihomoBridgeProxy) dialChecked(ctx context.Context, m *M.Metadata, host string, addresses []netip.Addr) (net.Conn, error) {
	if p.direct == nil {
		return nil, errDirectNameUnresolved
	}
	ctx, cancel := context.WithTimeout(ctx, C.DefaultTCPTimeout)
	defer cancel()
	attempt := C.DefaultTCPTimeout / time.Duration(len(addresses))
	var dialErr error
	for _, address := range addresses {
		if p.x.sessionGen.Load() != p.mark {
			return nil, errSessionEnded
		}
		metadata := &C.Metadata{
			NetWork: C.TCP,
			Type:    C.TUN,
			InName:  p.inName,
			SrcIP:   m.SrcIP,
			SrcPort: m.SrcPort,
			DstIP:   address,
			DstPort: m.DstPort,
		}
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, attempt)
		conn, err := p.direct.DialContext(attemptCtx, metadata)
		cancelAttempt()
		if err != nil {
			dialErr = err
			continue
		}
		if p.x.sessionGen.Load() != p.mark {
			_ = conn.Close()
			return nil, errSessionEnded
		}
		metadata.Host = host
		tracked := statistic.NewTCPTracker(conn, statistic.DefaultManager, metadata, nil, 0, 0, true)
		// The inbound the flow was routed by; the tunnel itself names its
		// force-direct sub-rule.
		tracked.TrackerInfo.Rule = C.InName.String()
		tracked.TrackerInfo.RulePayload = p.inName
		return tracked, nil
	}
	return nil, dialErr
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
	host, addresses, err := p.destination(context.Background(), dst.Addr())
	if err != nil {
		return nil, err
	}
	dialed := netip.AddrPortFrom(addresses[0], dst.Port())
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
