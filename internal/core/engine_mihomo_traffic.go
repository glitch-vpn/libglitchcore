//go:build !no_mihomo

package core

import (
	"context"
	"io"
	"net"
	"sync/atomic"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	mihomoCfg "github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// mihomo's totals count every connection, DIRECT ones too, and last the whole
// process; xray counts its proxy outbounds for one session. DIRECT is wrapped
// to count its own bytes, so mihomo too reports what the tunnel proxied since
// the session started.
type mihomoTraffic struct {
	baseUp, baseDown     atomic.Int64
	directUp, directDown atomic.Int64
}

var mihomoSessionTraffic mihomoTraffic

func (t *mihomoTraffic) startSession() {
	up, down := statistic.DefaultManager.Total()
	t.baseUp.Store(up)
	t.baseDown.Store(down)
	t.directUp.Store(0)
	t.directDown.Store(0)
}

func (t *mihomoTraffic) proxied() (uint64, uint64) {
	up, down := statistic.DefaultManager.Total()
	up -= t.baseUp.Load() + t.directUp.Load()
	down -= t.baseDown.Load() + t.directDown.Load()
	return uint64(max(down, 0)), uint64(max(up, 0))
}

// The adapter is swapped inside the parsed DIRECT proxy rather than the proxy
// replaced, so every group and the GLOBAL selector, built from that same
// proxy, reach the counted one too.
func countMihomoDirect(cfg *mihomoCfg.Config, t *mihomoTraffic) {
	if direct, ok := cfg.Proxies["DIRECT"].(*adapter.Proxy); ok {
		direct.ProxyAdapter = &countingAdapter{ProxyAdapter: direct.ProxyAdapter, traffic: t}
	}
}

type countingAdapter struct {
	C.ProxyAdapter
	traffic *mihomoTraffic
}

// mihomo's own dials (its DNS client's, say) are INNER and skip the manager's
// totals, so they are not taken out of them either.
func (a *countingAdapter) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	c, err := a.ProxyAdapter.DialContext(ctx, metadata)
	if err != nil || metadata.Type == C.INNER {
		return c, err
	}
	return &countedConn{Conn: c, traffic: a.traffic}, nil
}

func (a *countingAdapter) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	pc, err := a.ProxyAdapter.ListenPacketContext(ctx, metadata)
	if err != nil || metadata.Type == C.INNER {
		return pc, err
	}
	return &countedPacketConn{PacketConn: pc, traffic: a.traffic}, nil
}

// countedConn counts on every path the relay takes: plain and buffer reads
// and writes, and the count functions it collects when it unwraps a
// connection for a direct copy. It is not replaceable, or the relay would
// unwrap past it and the bytes would go uncounted.
type countedConn struct {
	C.Conn
	traffic *mihomoTraffic
}

func (c *countedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.traffic.directDown.Add(int64(n))
	return n, err
}

func (c *countedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.traffic.directUp.Add(int64(n))
	return n, err
}

func (c *countedConn) ReadBuffer(buffer *buf.Buffer) error {
	err := c.Conn.ReadBuffer(buffer)
	c.traffic.directDown.Add(int64(buffer.Len()))
	return err
}

func (c *countedConn) WriteBuffer(buffer *buf.Buffer) error {
	n := buffer.Len()
	err := c.Conn.WriteBuffer(buffer)
	c.traffic.directUp.Add(int64(n))
	return err
}

func (c *countedConn) UnwrapReader() (io.Reader, []N.CountFunc) {
	return c.Conn, []N.CountFunc{func(n int64) { c.traffic.directDown.Add(n) }}
}

func (c *countedConn) UnwrapWriter() (io.Writer, []N.CountFunc) {
	return c.Conn, []N.CountFunc{func(n int64) { c.traffic.directUp.Add(n) }}
}

func (c *countedConn) ReaderReplaceable() bool { return false }

func (c *countedConn) WriterReplaceable() bool { return false }

func (c *countedConn) Upstream() any { return c.Conn }

type countedPacketConn struct {
	C.PacketConn
	traffic *mihomoTraffic
}

func (c *countedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	c.traffic.directDown.Add(int64(n))
	return n, addr, err
}

func (c *countedPacketConn) WaitReadFrom() ([]byte, func(), net.Addr, error) {
	data, put, addr, err := c.PacketConn.WaitReadFrom()
	c.traffic.directDown.Add(int64(len(data)))
	return data, put, addr, err
}

func (c *countedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	c.traffic.directUp.Add(int64(n))
	return n, err
}

func (c *countedPacketConn) Upstream() any { return c.PacketConn }
