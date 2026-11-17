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

// xrayUDPQueueDatagrams is how many datagrams of one flow wait for its proxy;
// the rest are dropped, as UDP allows.
const xrayUDPQueueDatagrams = 64

// xrayUDPFlow is one app socket's datagrams to one destination, as the bridge
// pairs them: every reply reads as coming from dst. Its own goroutine opens
// the flow in xray and writes what the queue holds, so the stack's delivery
// goroutine never waits on a flow.
type xrayUDPFlow struct {
	queue chan []byte
	idle  *time.Timer
	done  chan struct{}

	mu     sync.Mutex
	closed bool
	link   *transport.Link
	cancel context.CancelFunc
}

// attach gives the flow the link xray opened for it, or reports that the flow
// has ended meanwhile.
func (f *xrayUDPFlow) attach(link *transport.Link, cancel context.CancelFunc) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return false
	}
	f.link, f.cancel = link, cancel
	return true
}

func (f *xrayUDPFlow) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	f.idle.Stop()
	close(f.done)
	if f.link != nil {
		_ = common.Close(f.link.Writer)
		_ = common.Interrupt(f.link.Reader)
		f.cancel()
	}
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

// sendDatagram queues the datagram for the flow's goroutine and drops it when
// the queue is full.
func (h *xrayTunHandler) sendDatagram(_ xrayUDPKey, flow *xrayUDPFlow, datagram []byte) {
	flow.idle.Reset(h.udpTimeout)
	select {
	case flow.queue <- append([]byte(nil), datagram...):
	default:
	}
}

// udpFlow is the flow for key. A new one runs on its own goroutine, which
// picks the inbound the process rules name, or uses in when the caller names
// one, and opens the flow in xray.
func (h *xrayTunHandler) udpFlow(key xrayUDPKey, in *xrayInbound, replies func() SN.PacketWriter) (*xrayUDPFlow, error) {
	h.udpMu.Lock()
	defer h.udpMu.Unlock()
	if flow, ok := h.udpFlows[key]; ok {
		return flow, nil
	}
	if h.x.sessionGen.Load() != h.mark {
		return nil, errSessionEnded
	}
	flow := &xrayUDPFlow{queue: make(chan []byte, xrayUDPQueueDatagrams), done: make(chan struct{})}
	flow.idle = time.AfterFunc(h.udpTimeout, func() { h.dropUDPFlow(key, flow) })
	if h.udpFlows == nil {
		h.udpFlows = make(map[xrayUDPKey]*xrayUDPFlow)
	}
	h.udpFlows[key] = flow
	go h.runUDPFlow(key, flow, in, replies())
	return flow, nil
}

// runUDPFlow opens the flow in xray and carries the queued datagrams into it
// until the flow ends.
func (h *xrayTunHandler) runUDPFlow(key xrayUDPKey, flow *xrayUDPFlow, in *xrayInbound, back SN.PacketWriter) {
	defer h.dropUDPFlow(key, flow)
	if in == nil {
		var err error
		if in, err = h.inboundFor("udp", key.src); err != nil {
			return
		}
	}
	dest := xrayAddrDestination(xrayNet.Network_UDP, key.dst)
	ctx, cancel := in.flowContext(xrayAddrDestination(xrayNet.Network_UDP, key.src), dest)
	link, err := in.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		cancel()
		return
	}
	if !flow.attach(link, cancel) {
		cancel()
		return
	}
	go h.writeReplies(key, flow, back)
	for {
		select {
		case datagram := <-flow.queue:
			b := buf.NewWithSize(int32(len(datagram)))
			_, _ = b.Write(datagram)
			if err := link.Writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				return
			}
		case <-flow.done:
			return
		}
	}
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
