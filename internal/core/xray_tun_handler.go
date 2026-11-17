//go:build !no_xray && !with_tun2socks

package core

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	tun "github.com/metacubex/sing-tun"
	sbuf "github.com/metacubex/sing/common/buf"
	SM "github.com/metacubex/sing/common/metadata"
	SN "github.com/metacubex/sing/common/network"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xrayNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// xrayTunHandler takes sing-tun's flows into xray: the app's under the app
// tag, a flow whose process a rule names under the force-proxy or
// force-direct tag, so the tiers' blocks still meet it.
type xrayTunHandler struct {
	x           *CoreController
	mark        int64
	app         *xrayInbound
	forceProxy  *xrayInbound // nil when no process->proxy rule
	forceDirect *xrayInbound // nil when no process->direct rule
	split       processSplit
	udpTimeout  time.Duration

	udpMu    sync.Mutex
	udpFlows map[xrayUDPKey]*xrayUDPFlow
}

var _ tun.Handler = (*xrayTunHandler)(nil)

// inboundFor picks the inbound a flow from src enters by.
func (h *xrayTunHandler) inboundFor(network string, src netip.AddrPort) (*xrayInbound, error) {
	switch h.split.target(network, src) {
	case routing.TargetBlock:
		return nil, errProcessBlocked
	case routing.TargetDirect:
		if h.forceDirect == nil {
			return nil, errNoForceDirect
		}
		return h.forceDirect, nil
	case routing.TargetProxy:
		if h.forceProxy != nil {
			return h.forceProxy, nil
		}
	}
	return h.app, nil
}

// PrepareConnection is asked for ICMP alone on the gVisor stack. No route
// declines the echo request, so the stack drops it: nothing answers a ping
// the exit never carried.
func (h *xrayTunHandler) PrepareConnection(string, SM.Socksaddr, SM.Socksaddr, tun.DirectRouteContext, time.Duration) (tun.DirectRouteDestination, error) {
	return nil, nil
}

func (h *xrayTunHandler) NewConnection(_ context.Context, conn net.Conn, metadata SM.Metadata) error {
	defer conn.Close()
	src, dst := metadata.Source.Unwrap().AddrPort(), metadata.Destination.Unwrap().AddrPort()
	in, err := h.inboundFor("tcp", src)
	if err != nil {
		return err
	}
	return h.serveTCP(in, conn, src, dst)
}

// serveTCP carries one flow into xray under in until either side ends it.
func (h *xrayTunHandler) serveTCP(in *xrayInbound, conn net.Conn, src, dst netip.AddrPort) error {
	if h.x.sessionGen.Load() != h.mark {
		return errSessionEnded
	}
	dest := xrayAddrDestination(xrayNet.Network_TCP, dst)
	ctx, cancel := in.flowContext(xrayAddrDestination(xrayNet.Network_TCP, src), dest)
	defer cancel()
	link := &transport.Link{Reader: buf.NewReader(conn), Writer: buf.NewWriter(conn)}
	return in.dispatcher.DispatchLink(ctx, dest, link)
}

type xrayUDPKey struct{ src, dst netip.AddrPort }

// xrayUDPFlow is one app socket's datagrams to one destination, as the bridge
// pairs them: every reply reads as coming from dst.
type xrayUDPFlow struct {
	link      *transport.Link
	cancel    context.CancelFunc
	idle      *time.Timer
	closeOnce sync.Once
}

func (f *xrayUDPFlow) close() {
	f.closeOnce.Do(func() {
		f.idle.Stop()
		_ = common.Close(f.link.Writer)
		_ = common.Interrupt(f.link.Reader)
		f.cancel()
	})
}

func (h *xrayTunHandler) NewPacket(_ context.Context, key netip.AddrPort, buffer *sbuf.Buffer, metadata SM.Metadata, init func(SN.PacketConn) SN.PacketWriter) {
	defer buffer.Release()
	dst := metadata.Destination.Unwrap().AddrPort()
	flowKey := xrayUDPKey{src: key, dst: dst}
	flow, err := h.udpFlow(flowKey, nil, func() SN.PacketWriter { return init(nil) })
	if err != nil {
		return
	}
	h.sendDatagram(flowKey, flow, buffer.Bytes())
}

func (h *xrayTunHandler) sendDatagram(key xrayUDPKey, flow *xrayUDPFlow, datagram []byte) {
	flow.idle.Reset(h.udpTimeout)
	b := buf.NewWithSize(int32(len(datagram)))
	_, _ = b.Write(datagram)
	if err := flow.link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		h.dropUDPFlow(key, flow)
	}
}

// udpFlow is the flow for key, opened on its first datagram under the inbound
// the process rules pick, or in when the caller names one.
func (h *xrayTunHandler) udpFlow(key xrayUDPKey, in *xrayInbound, replies func() SN.PacketWriter) (*xrayUDPFlow, error) {
	h.udpMu.Lock()
	defer h.udpMu.Unlock()
	if flow, ok := h.udpFlows[key]; ok {
		return flow, nil
	}
	if h.x.sessionGen.Load() != h.mark {
		return nil, errSessionEnded
	}
	if in == nil {
		var err error
		if in, err = h.inboundFor("udp", key.src); err != nil {
			return nil, err
		}
	}
	dest := xrayAddrDestination(xrayNet.Network_UDP, key.dst)
	ctx, cancel := in.flowContext(xrayAddrDestination(xrayNet.Network_UDP, key.src), dest)
	link, err := in.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		cancel()
		return nil, err
	}
	flow := &xrayUDPFlow{link: link, cancel: cancel}
	flow.idle = time.AfterFunc(h.udpTimeout, func() { h.dropUDPFlow(key, flow) })
	if h.udpFlows == nil {
		h.udpFlows = make(map[xrayUDPKey]*xrayUDPFlow)
	}
	h.udpFlows[key] = flow
	go h.writeReplies(key, flow, replies())
	return flow, nil
}

func (h *xrayTunHandler) writeReplies(key xrayUDPKey, flow *xrayUDPFlow, back SN.PacketWriter) {
	defer h.dropUDPFlow(key, flow)
	from := SM.SocksaddrFromNetIP(key.dst)
	for {
		mb, err := flow.link.Reader.ReadMultiBuffer()
		for _, datagram := range mb {
			if sender := xraySender(datagram.UDP); sender.IsValid() && sender != netip.AddrPortFrom(key.dst.Addr().Unmap(), key.dst.Port()) {
				continue
			}
			reply := sbuf.NewSize(int(datagram.Len()))
			_, _ = reply.Write(datagram.Bytes())
			_ = back.WritePacket(reply, from)
		}
		buf.ReleaseMulti(mb)
		if err != nil {
			return
		}
		flow.idle.Reset(h.udpTimeout)
	}
}

func (h *xrayTunHandler) dropUDPFlow(key xrayUDPKey, flow *xrayUDPFlow) {
	h.udpMu.Lock()
	if h.udpFlows[key] == flow {
		delete(h.udpFlows, key)
	}
	h.udpMu.Unlock()
	flow.close()
}

func (h *xrayTunHandler) closeUDPFlows() {
	h.udpMu.Lock()
	flows := h.udpFlows
	h.udpFlows = nil
	h.udpMu.Unlock()
	for _, flow := range flows {
		flow.close()
	}
}

func (h *xrayTunHandler) NewError(_ context.Context, err error) {
	logfmt.Warnf("[tun] %v", err)
}
