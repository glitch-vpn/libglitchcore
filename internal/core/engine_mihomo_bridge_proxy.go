//go:build !no_mihomo && (!no_xray || !no_awg)

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
// a TUN inbound would. Once its session has ended it refuses every flow.
type mihomoBridgeProxy struct {
	x         *CoreController
	mark      int64
	inName    string // the IN-NAME rule's name for force-proxy flows, else ""
	hijackDNS bool
}

func (p *mihomoBridgeProxy) DialContext(_ context.Context, m *M.Metadata) (net.Conn, error) {
	if p.x.sessionGen.Load() != p.mark {
		return nil, errSessionEnded
	}
	local, engine := bridgePipe()
	if p.hijackDNS && m.DstPort == 53 {
		go func() { _ = resolver.RelayDnsConn(context.Background(), engine, resolver.DefaultDnsReadTimeout) }()
		return local, nil
	}
	metadata := &C.Metadata{
		NetWork: C.TCP,
		Type:    C.TUN,
		InName:  p.inName,
		SrcIP:   m.SrcIP,
		SrcPort: m.SrcPort,
		DstIP:   m.DstIP,
		DstPort: m.DstPort,
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
	if p.hijackDNS && m.DstPort == 53 {
		flow = newBridgeFlowConn(dst, func(query []byte) error {
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
	// mihomo keys its UDP NAT on the source address's text, and tun2socks
	// hands over one flow per destination: a per-flow key keeps two flows
	// from one app port apart, while the address underneath stays the app's.
	src := N.NewCustomAddr(C.TUN.String(), fmt.Sprintf("bridge-%d", mihomoBridgeFlowID.Add(1)),
		net.UDPAddrFromAddrPort(m.SourceAddrPort()))
	target := socks5.ParseAddrToSocksAddr(net.UDPAddrFromAddrPort(dst))
	// Each datagram is matched anew once its NAT entry lapses, and mihomo's
	// tunnel outlives the session with only DIRECT left.
	flow = newBridgeFlowConn(dst, func(b []byte) error {
		if p.x.sessionGen.Load() != p.mark {
			return errSessionEnded
		}
		data := pool.Get(len(b))
		copy(data, b)
		packet, metadata := inbound.NewPacket(target, &mihomoBridgePacket{flow: flow, src: src, data: data}, C.TUN, inbound.WithInName(p.inName))
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
