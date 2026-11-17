//go:build !no_xray && with_tun2socks

package core

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xrayNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
)

var _ t2sproxy.Proxy = (*xrayBridgeProxy)(nil)

// newXrayBridgeProxy hands tun2socks's flows to xray in process, as the
// inbound would. Once its session has ended it refuses every flow.
func (x *CoreController) newXrayBridgeProxy(in *xrayInbound, mark int64) *xrayBridgeProxy {
	return &xrayBridgeProxy{x: x, mark: mark, inbound: in}
}

type xrayBridgeProxy struct {
	x       *CoreController
	mark    int64
	inbound *xrayInbound
}

func (p *xrayBridgeProxy) dispatch(m *M.Metadata, network xrayNet.Network) (*transport.Link, context.CancelFunc, error) {
	if p.x.sessionGen.Load() != p.mark {
		return nil, nil, errSessionEnded
	}
	src := xrayAddrDestination(network, netip.AddrPortFrom(m.SrcIP, m.SrcPort))
	dest := xrayAddrDestination(network, netip.AddrPortFrom(m.DstIP, m.DstPort))
	ctx, cancel := p.inbound.flowContext(src, dest)
	link, err := p.inbound.dispatcher.Dispatch(ctx, dest)
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
	flow := newBridgeFlowConn(m.DestinationAddrPort(), m.DestinationAddrPort(), func(b []byte) error {
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
