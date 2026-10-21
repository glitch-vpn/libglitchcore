//go:build !no_xray || (!no_mihomo && !no_awg)

package core

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

const bridgeFlowQueue = 128

// bridgeFlowConn is one tun2socks UDP flow handed to an engine in process.
// tun2socks pairs a flow with one destination, so every reply reads as coming
// from dst, and one an engine reports from elsewhere is dropped here, as
// tun2socks would.
type bridgeFlowConn struct {
	dst     netip.AddrPort
	send    func([]byte) error
	release func()

	replies      chan []byte
	done         chan struct{}
	closeOnce    sync.Once
	readDeadline bridgeDeadline
}

// send must not keep the slice it is given past its return.
func newBridgeFlowConn(dst netip.AddrPort, send func([]byte) error, release func()) *bridgeFlowConn {
	return &bridgeFlowConn{
		dst:          dst,
		send:         send,
		release:      release,
		replies:      make(chan []byte, bridgeFlowQueue),
		done:         make(chan struct{}),
		readDeadline: bridgeDeadline{expired: make(chan struct{})},
	}
}

// deliver queues a copy of a reply; a full queue drops it, as a socket
// buffer would.
func (c *bridgeFlowConn) deliver(b []byte) error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	select {
	case c.replies <- append([]byte(nil), b...):
	default:
	}
	return nil
}

// deliverFrom drops a reply from a sender other than dst; an invalid from is
// one the engine names by domain, which is dst by construction.
func (c *bridgeFlowConn) deliverFrom(b []byte, from netip.AddrPort) error {
	if from.IsValid() && netip.AddrPortFrom(from.Addr().Unmap(), from.Port()) != c.dst {
		return nil
	}
	return c.deliver(b)
}

func (c *bridgeFlowConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.done:
		return 0, nil, net.ErrClosed
	default:
	}
	select {
	case b := <-c.replies:
		return copy(p, b), net.UDPAddrFromAddrPort(c.dst), nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *bridgeFlowConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	if err := c.send(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *bridgeFlowConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.readDeadline.set(time.Time{})
		if c.release != nil {
			c.release()
		}
	})
	return nil
}

func (c *bridgeFlowConn) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (c *bridgeFlowConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *bridgeFlowConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return nil
}

// Writes never wait, so there is nothing for a write deadline to bound.
func (c *bridgeFlowConn) SetWriteDeadline(time.Time) error { return nil }

// bridgeDeadline reuses its channel while it is open, so a read already
// waiting sees a deadline moved by another goroutine: tun2socks extends a
// flow's read deadline from the opposite direction's copy loop.
type bridgeDeadline struct {
	mu      sync.Mutex
	timer   *time.Timer
	expired chan struct{}
}

func (d *bridgeDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.expired
	}
	d.timer = nil
	closed := isClosedChan(d.expired)
	if t.IsZero() {
		if closed {
			d.expired = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.expired = make(chan struct{})
		}
		expired := d.expired
		d.timer = time.AfterFunc(dur, func() { close(expired) })
		return
	}
	if !closed {
		close(d.expired)
	}
}

func (d *bridgeDeadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.expired
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
