//go:build !no_xray && !with_tun2socks

package core

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sbuf "github.com/metacubex/sing/common/buf"
	SM "github.com/metacubex/sing/common/metadata"
	SN "github.com/metacubex/sing/common/network"
	"github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"
)

// tunEntry enters flows through the sing-tun handler under one inbound tag,
// where the stack would hand them over after its handshake. A destination the
// gVisor stack would bounce back to the app (loopback) reaches xray all the
// same, which is how a test observes where a flow went.
type tunEntry struct {
	handler  *xrayTunHandler
	inbound  *xrayInbound
	nextPort atomic.Uint32
}

var tunEntryApp = netip.MustParseAddr("198.18.0.2")

func newXrayEntry(t *testing.T, x *CoreController, inst *xrayCore.Instance, tag string, sniffing session.SniffingRequest) xrayEntry {
	t.Helper()
	inbound, err := newXrayInbound(inst, tag, sniffing)
	if err != nil {
		t.Fatal(err)
	}
	handler := &xrayTunHandler{x: x, mark: x.sessionGen.Load(), udpTimeout: 30 * time.Second}
	t.Cleanup(handler.closeUDPFlows)
	e := &tunEntry{handler: handler, inbound: inbound}
	e.nextPort.Store(40000)
	return e
}

func (e *tunEntry) source() netip.AddrPort {
	return netip.AddrPortFrom(tunEntryApp, uint16(e.nextPort.Add(1)))
}

func (e *tunEntry) DialTCP(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	app, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return nil, err
	}
	stackSide, err := listener.Accept()
	if err != nil {
		_ = app.Close()
		return nil, err
	}
	ended := make(chan error, 1)
	go func() {
		defer stackSide.Close()
		ended <- e.handler.serveTCP(e.inbound, stackSide, e.source(), dst)
	}()
	// A flow the session has ended refuses at once; any other runs until an
	// end closes it.
	select {
	case err := <-ended:
		_ = app.Close()
		if err != nil {
			return nil, err
		}
		return nil, net.ErrClosed
	case <-time.After(100 * time.Millisecond):
		return app, nil
	}
}

func (e *tunEntry) DialUDP(dst netip.AddrPort) (net.PacketConn, error) {
	key := xrayUDPKey{src: e.source(), dst: dst}
	replies := make(chan []byte, 64)
	flow, err := e.handler.udpFlow(key, e.inbound, func() SN.PacketWriter { return replyQueue(replies) })
	if err != nil {
		return nil, err
	}
	return &tunPacketConn{handler: e.handler, key: key, flow: flow, replies: replies}, nil
}

// replyQueue is the stack's way back to the app, as a channel.
type replyQueue chan []byte

func (q replyQueue) WritePacket(buffer *sbuf.Buffer, _ SM.Socksaddr) error {
	defer buffer.Release()
	select {
	case q <- append([]byte(nil), buffer.Bytes()...):
	default:
	}
	return nil
}

// tunPacketConn is one app socket's side of a UDP flow.
type tunPacketConn struct {
	handler *xrayTunHandler
	key     xrayUDPKey
	flow    *xrayUDPFlow
	replies chan []byte

	mu       sync.Mutex
	deadline time.Time
}

func (c *tunPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.handler.sendDatagram(c.key, c.flow, b)
	return len(b), nil
}

func (c *tunPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	var expired <-chan time.Time
	if !deadline.IsZero() {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case reply := <-c.replies:
		return copy(b, reply), net.UDPAddrFromAddrPort(c.key.dst), nil
	case <-expired:
		return 0, nil, timeoutError{}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func (c *tunPacketConn) Close() error {
	c.handler.dropUDPFlow(c.key, c.flow)
	return nil
}

func (c *tunPacketConn) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(c.key.src) }

func (c *tunPacketConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *tunPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

func (c *tunPacketConn) SetWriteDeadline(time.Time) error { return nil }
