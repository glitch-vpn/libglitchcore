//go:build !no_xray || (!no_mihomo && !no_awg)

package core

import (
	"context"
	"net"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"
)

var _ t2sproxy.Proxy = (*dnsRedirectProxy)(nil)

// dnsRedirectProxy diverts :53 (TCP+UDP) to mihomo's own loopback DNS server.
// mihomo can't dns-hijack without a TUN, so this bridge-level redirect stands in
// for it (fake-ip mode); non-DNS traffic passes straight through to base.
type dnsRedirectProxy struct {
	base    t2sproxy.Proxy
	dnsAddr string
}

func (p *dnsRedirectProxy) DialContext(ctx context.Context, m *M.Metadata) (net.Conn, error) {
	if m != nil && m.DstPort == 53 {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", p.dnsAddr)
	}
	return p.base.DialContext(ctx, m)
}

func (p *dnsRedirectProxy) DialUDP(m *M.Metadata) (net.PacketConn, error) {
	if m == nil || m.DstPort != 53 {
		return p.base.DialUDP(m)
	}
	c, err := net.Dial("udp", p.dnsAddr)
	if err != nil {
		return nil, err
	}
	// tun2socks' symmetric-NAT wrapper drops any reply whose source != the queried
	// destination, so report the original queried address (not the DNS server).
	return &dnsPacketConn{conn: c.(*net.UDPConn), report: m.UDPAddr()}, nil
}

// dnsPacketConn: writes go to the fixed DNS server (addr ignored); reads report
// the original queried address so tun2socks' NAT check passes.
type dnsPacketConn struct {
	conn   *net.UDPConn
	report net.Addr
}

func (c *dnsPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.conn.Write(b) }

func (c *dnsPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.conn.Read(b)
	return n, c.report, err
}

func (c *dnsPacketConn) Close() error                       { return c.conn.Close() }
func (c *dnsPacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *dnsPacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *dnsPacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *dnsPacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
