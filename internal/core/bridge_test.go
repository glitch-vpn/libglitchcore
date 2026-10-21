//go:build !no_xray || (!no_mihomo && !no_awg)

package core

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	D "github.com/miekg/dns"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	t2sproxy "github.com/xjasonlyu/tun2socks/v2/proxy"
)

const bridgeTestVlessLink = "vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=tcp&security=none#t"

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

// tcpEcho echoes until the client half-closes, then writes "eof" and closes,
// so a client that half-closes sees "eof" only if its FIN reached the server.
func tcpEcho(t *testing.T) net.Addr {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
				_, _ = c.Write([]byte("eof"))
			}(c)
		}
	}()
	return l.Addr()
}

func udpEcho(t *testing.T) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], from)
		}
	}()
	return pc.LocalAddr()
}

// requireTCPRoundTrip half-closes after its request: the flow must still end,
// which it does only if the half-close reached the engine. want is what the
// app reads back: xray's direct outbound ends the flow without passing the
// FIN on, so its server never writes "eof".
func requireTCPRoundTrip(t *testing.T, p t2sproxy.Proxy, echo net.Addr, want string) {
	t.Helper()
	conn, err := p.DialContext(t.Context(), bridgeTestFlow(M.TCP, echo))
	if err != nil {
		t.Fatalf("dial tcp %s: %v", echo, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	cw, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("%T cannot half-close", conn)
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}
	got := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(conn)
		got <- b
	}()
	select {
	case b := <-got:
		if string(b) != want {
			t.Fatalf("tcp through the bridge read %q, want %q", b, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("tcp through the bridge: no answer")
	}
}

func requireUDPRoundTrip(t *testing.T, pc net.PacketConn, echo net.Addr, payload []byte) {
	t.Helper()
	b := make([]byte, 65535)
	for i := 0; i < 10; i++ {
		if _, err := pc.WriteTo(payload, echo); err != nil {
			t.Fatalf("write udp: %v", err)
		}
		_ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, from, err := pc.ReadFrom(b)
		if err != nil {
			continue
		}
		if string(b[:n]) != string(payload) {
			t.Fatalf("udp through the bridge read %d bytes, want the %d sent", n, len(payload))
		}
		if from.String() != echo.String() {
			t.Fatalf("reply reads as from %s, want %s (tun2socks drops any other)", from, echo)
		}
		return
	}
	t.Fatalf("udp through the bridge: no answer from %s", echo)
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
	flow := newBridgeFlowConn(netip.AddrPort{}, func([]byte) error { return nil }, nil)
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
	flow := newBridgeFlowConn(netip.AddrPort{}, func([]byte) error { return nil }, func() { released = true })
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

func requireFakeIPAnswer(t *testing.T, pc net.PacketConn, resolver net.Addr, pool string) {
	t.Helper()
	q := new(D.Msg)
	q.SetQuestion("example.com.", D.TypeA)
	query, _ := q.Pack()
	b := make([]byte, 2048)
	for i := 0; i < 10; i++ {
		_, _ = pc.WriteTo(query, resolver)
		_ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := pc.ReadFrom(b)
		if err != nil {
			continue
		}
		r := new(D.Msg)
		if err := r.Unpack(b[:n]); err != nil || len(r.Answer) == 0 {
			t.Fatalf("answer %v, err %v", r, err)
		}
		if a, ok := r.Answer[0].(*D.A); !ok || !strings.HasPrefix(a.A.String(), pool) {
			t.Fatalf("answer %v, want a fake IP in %s*", r.Answer[0], pool)
		}
		return
	}
	t.Fatal("no DNS answer through the bridge")
}

// udpReflector answers from a second socket: a third party the flow never
// addressed. It returns the address the flow sends to.
func udpReflector(t *testing.T) net.Addr {
	t.Helper()
	in, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = out.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := in.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = out.WriteTo(b[:n], from)
		}
	}()
	return in.LocalAddr()
}

func requireNoThirdPartyReply(t *testing.T, p t2sproxy.Proxy) {
	t.Helper()
	dst := udpReflector(t)
	pc, err := p.DialUDP(bridgeTestFlow(M.UDP, dst))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer pc.Close()
	b := make([]byte, 64)
	for i := 0; i < 5; i++ {
		_, _ = pc.WriteTo([]byte("probe"), dst)
		_ = pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if n, from, err := pc.ReadFrom(b); err == nil {
			t.Fatalf("a reply from a third party reached the app as from %s: %q", from, b[:n])
		}
	}
}

func TestBridgeFlowConn_DropsRepliesFromOtherSenders(t *testing.T) {
	dst := netip.MustParseAddrPort("192.0.2.7:53")
	flow := newBridgeFlowConn(dst, func([]byte) error { return nil }, nil)
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
