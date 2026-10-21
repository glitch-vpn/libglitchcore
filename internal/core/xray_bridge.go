//go:build !no_xray

package core

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xrayCtx "github.com/xtls/xray-core/common/ctx"
	xrayLog "github.com/xtls/xray-core/common/log"
	xrayNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

var _ t2sproxy.Proxy = (*xrayBridgeProxy)(nil)

type xrayInstanceContext struct{}

func init() {
	common.Must(common.RegisterConfig((*xrayInstanceContext)(nil), func(ctx context.Context, _ interface{}) (interface{}, error) {
		return ctx, nil
	}))
}

// newXrayBridgeProxy hands tun2socks's flows to xray in process, as the
// inbound tagged tag would. Once its session has ended it refuses every flow.
func (x *CoreController) newXrayBridgeProxy(inst *xrayCore.Instance, tag string, sniffing session.SniffingRequest, mark int64) (*xrayBridgeProxy, error) {
	// The instance's own context, which xray's inbounds derive a
	// connection's from: per-connection code such as the fake-DNS sniffer
	// reads the instance out of it.
	instCtx, err := xrayCore.CreateObject(inst, (*xrayInstanceContext)(nil))
	if err != nil {
		return nil, err
	}
	dispatcher, ok := inst.GetFeature(routing.DispatcherType()).(routing.Dispatcher)
	if !ok {
		return nil, fmt.Errorf("xray has no dispatcher")
	}
	return &xrayBridgeProxy{
		x:          x,
		mark:       mark,
		ctx:        instCtx.(context.Context),
		dispatcher: dispatcher,
		tag:        tag,
		sniffing:   sniffing,
	}, nil
}

type xrayBridgeProxy struct {
	x          *CoreController
	mark       int64
	ctx        context.Context
	dispatcher routing.Dispatcher
	tag        string
	sniffing   session.SniffingRequest
}

// dispatch hands one flow to xray as its inbound worker would. xray ends the
// flow when its context is cancelled, so the context outlives the dial and
// only the caller's close cancels it.
func (p *xrayBridgeProxy) dispatch(m *M.Metadata, network xrayNet.Network) (*transport.Link, context.CancelFunc, error) {
	if p.x.sessionGen.Load() != p.mark {
		return nil, nil, errSessionEnded
	}
	src := xrayNet.Destination{Network: network, Address: xrayNet.IPAddress(m.SrcIP.AsSlice()), Port: xrayNet.Port(m.SrcPort)}
	dest := xrayNet.Destination{Network: network, Address: xrayNet.IPAddress(m.DstIP.AsSlice()), Port: xrayNet.Port(m.DstPort)}
	ctx, cancel := context.WithCancel(p.ctx)
	ctx = xrayCtx.ContextWithID(ctx, session.NewID())
	// CanSpliceCopy 3: no raw socket backs the flow, so xray must copy.
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Source: src, Tag: p.tag, CanSpliceCopy: 3})
	ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest: p.sniffing})
	ctx = xrayLog.ContextWithAccessMessage(ctx, &xrayLog.AccessMessage{From: src, To: dest, Status: xrayLog.AccessAccepted})
	link, err := p.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return link, cancel, nil
}

func (p *xrayBridgeProxy) DialContext(_ context.Context, m *M.Metadata) (net.Conn, error) {
	link, cancel, err := p.dispatch(m, xrayNet.Network_TCP)
	if err != nil {
		return nil, err
	}
	return &xrayLinkConn{reader: &buf.BufferedReader{Reader: link.Reader}, link: link, cancel: cancel}, nil
}

// Each datagram crosses xray's link as one buffer each way.
func (p *xrayBridgeProxy) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	link, cancel, err := p.dispatch(m, xrayNet.Network_UDP)
	if err != nil {
		return nil, err
	}
	flow := newBridgeFlowConn(m.DestinationAddrPort(), func(b []byte) error {
		datagram := buf.NewWithSize(int32(len(b)))
		_, _ = datagram.Write(b)
		return link.Writer.WriteMultiBuffer(buf.MultiBuffer{datagram})
	}, func() {
		_ = common.Close(link.Writer)
		_ = common.Interrupt(link.Reader)
		cancel()
	})
	go func() {
		defer flow.Close()
		for {
			mb, err := link.Reader.ReadMultiBuffer()
			for _, datagram := range mb {
				_ = flow.deliverFrom(datagram.Bytes(), xraySender(datagram.UDP))
			}
			buf.ReleaseMulti(mb)
			if err != nil {
				return
			}
		}
	}()
	return flow, nil
}

// xraySender is the address a reply came from, or invalid when xray names it
// by domain (fake-ip) or not at all.
func xraySender(from *xrayNet.Destination) netip.AddrPort {
	if from == nil || !from.Address.Family().IsIP() {
		return netip.AddrPort{}
	}
	ip, ok := netip.AddrFromSlice(from.Address.IP())
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(from.Port))
}

// xrayLinkConn is the TCP side of a flow's link. CloseWrite ends the uplink,
// so an app's half-close reaches the server as it would through a socket.
// xray bounds a half-closed flow itself, so deadlines are not kept.
type xrayLinkConn struct {
	reader    *buf.BufferedReader
	link      *transport.Link
	cancel    context.CancelFunc
	closeOnce sync.Once
}

func (c *xrayLinkConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func (c *xrayLinkConn) Write(b []byte) (int, error) {
	if err := c.link.Writer.WriteMultiBuffer(buf.MergeBytes(nil, b)); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *xrayLinkConn) CloseWrite() error { return common.Close(c.link.Writer) }

func (c *xrayLinkConn) Close() error {
	c.closeOnce.Do(func() {
		_ = common.Close(c.link.Writer)
		_ = common.Interrupt(c.link.Reader)
		c.cancel()
	})
	return nil
}

func (c *xrayLinkConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *xrayLinkConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *xrayLinkConn) SetDeadline(time.Time) error      { return nil }
func (c *xrayLinkConn) SetReadDeadline(time.Time) error  { return nil }
func (c *xrayLinkConn) SetWriteDeadline(time.Time) error { return nil }
