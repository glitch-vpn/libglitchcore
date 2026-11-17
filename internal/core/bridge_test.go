//go:build !no_xray && with_tun2socks

package core

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"testing"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"
)

// An app on the TUN, as tun2socks reports it.
var bridgeTestApp = netip.MustParseAddrPort("198.18.0.1:40000")

func bridgeTestFlow(network M.Network, dst net.Addr) *M.Metadata {
	ap := netip.MustParseAddrPort(dst.String())
	return &M.Metadata{
		Network: network,
		SrcIP:   bridgeTestApp.Addr(),
		SrcPort: bridgeTestApp.Port(),
		DstIP:   ap.Addr(),
		DstPort: ap.Port(),
	}
}

// bridgeEntry enters flows through a bridge proxy, as tun2socks hands them over.
type bridgeEntry struct{ proxy t2sproxy.Proxy }

func (e bridgeEntry) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return e.proxy.DialContext(ctx, bridgeTestFlow(M.TCP, net.TCPAddrFromAddrPort(dst)))
}

func (e bridgeEntry) DialUDP(dst netip.AddrPort) (net.PacketConn, error) {
	return e.proxy.DialUDP(bridgeTestFlow(M.UDP, net.UDPAddrFromAddrPort(dst)))
}

func newXrayEntry(t *testing.T, x *CoreController, inst *xrayCore.Instance, tag string, sniffing session.SniffingRequest) xrayEntry {
	t.Helper()
	in, err := newXrayInbound(inst, tag, sniffing)
	if err != nil {
		t.Fatal(err)
	}
	return bridgeEntry{x.newXrayBridgeProxy(in, x.sessionGen.Load())}
}

func TestBridgeProxyScheme_ServesTheSessionProxy(t *testing.T) {
	u, err := url.Parse(bridgeProxyURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := t2sproxy.Parse(u); err == nil {
		t.Fatal("the scheme must fail with no session proxy, or tun2socks would start without one")
	}
	session := &bridgeFlowProbeProxy{}
	setBridgeProxy(session)
	t.Cleanup(func() { setBridgeProxy(nil) })
	got, err := t2sproxy.Parse(u)
	if err != nil || got != session {
		t.Fatalf("Parse(%s) = %v, %v; want the session proxy", bridgeProxyURL, got, err)
	}
}

type bridgeFlowProbeProxy struct{ t2sproxy.Proxy }

func TestBridgeFlowConn_DeadlineMovedWhileReading(t *testing.T) {
	flow := newBridgeFlowConn(netip.AddrPort{}, netip.AddrPort{}, func([]byte) error { return nil }, nil)
	defer flow.Close()
	_ = flow.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	read := make(chan error, 1)
	go func() {
		_, _, err := flow.ReadFrom(make([]byte, 8))
		read <- err
	}()
	time.Sleep(30 * time.Millisecond)
	_ = flow.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	select {
	case err := <-read:
		t.Fatalf("read ended at the old deadline: %v", err)
	case <-time.After(250 * time.Millisecond):
	}
	select {
	case err := <-read:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("read past the deadline returned %v, want a timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("read outlived its moved deadline")
	}
}

func TestBridgeFlowConn_ClosedFlowRefusesReplies(t *testing.T) {
	released := false
	flow := newBridgeFlowConn(netip.AddrPort{}, netip.AddrPort{}, func([]byte) error { return nil }, func() { released = true })
	_ = flow.Close()
	if !released {
		t.Fatal("close did not release the engine side")
	}
	if err := flow.deliver([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("deliver after close = %v, want net.ErrClosed", err)
	}
	if _, _, err := flow.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after close = %v, want net.ErrClosed", err)
	}
}

func TestCapTun2socksLogLevel_KeepsFlowAddressesOut(t *testing.T) {
	for _, level := range []string{"info", "debug", "trace"} {
		if got := capTun2socksLogLevel(level); got != "warn" {
			t.Fatalf("capTun2socksLogLevel(%q) = %q, want warn", level, got)
		}
	}
	for _, level := range []string{"silent", "warn", "warning", "error", "fatal", "panic"} {
		if got := capTun2socksLogLevel(level); got != level {
			t.Fatalf("capTun2socksLogLevel(%q) = %q, want unchanged", level, got)
		}
	}
}

func TestBridgeFlowConn_DropsRepliesFromOtherSenders(t *testing.T) {
	dst := netip.MustParseAddrPort("192.0.2.7:53")
	flow := newBridgeFlowConn(dst, dst, func([]byte) error { return nil }, nil)
	defer flow.Close()
	_ = flow.deliverFrom([]byte("spoof"), netip.MustParseAddrPort("192.0.2.8:53"))
	_ = flow.deliverFrom([]byte("real"), netip.MustParseAddrPort("[::ffff:192.0.2.7]:53"))
	b := make([]byte, 8)
	_ = flow.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err := flow.ReadFrom(b)
	if err != nil || string(b[:n]) != "real" || from.String() != dst.String() {
		t.Fatalf("read %q from %v, %v; want only the reply from %s", b[:n], from, err, dst)
	}
}
