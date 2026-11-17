//go:build !no_xray

package core

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

// xrayEntry is where a test's flows enter an xray session: the bridge's proxy
// in the tun2socks variant, the sing-tun handler in the main one.
type xrayEntry interface {
	DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	DialUDP(dst netip.AddrPort) (net.PacketConn, error)
}

func addrPortOf(a net.Addr) netip.AddrPort {
	return netip.MustParseAddrPort(a.String())
}

// requireTCPRoundTrip half-closes after its request: the flow must still end,
// which it does only if the half-close reached the engine. want is what the
// app reads back: xray's direct outbound ends the flow without passing the
// FIN on, so its server never writes "eof".
func requireTCPRoundTrip(t *testing.T, e xrayEntry, echo net.Addr, want string) {
	t.Helper()
	conn, err := e.DialTCP(t.Context(), addrPortOf(echo))
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
			t.Fatalf("tcp through the TUN layer read %q, want %q", b, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("tcp through the TUN layer: no answer")
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
			t.Fatalf("udp through the TUN layer read %d bytes, want the %d sent", n, len(payload))
		}
		if from.String() != echo.String() {
			t.Fatalf("reply reads as from %s, want %s (the stack drops any other)", from, echo)
		}
		return
	}
	t.Fatalf("udp through the TUN layer: no answer from %s", echo)
}

func requireNoThirdPartyReply(t *testing.T, e xrayEntry) {
	t.Helper()
	dst := udpReflector(t)
	pc, err := e.DialUDP(addrPortOf(dst))
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

const vlessTestLink = "vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=tcp&security=none#t"

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
	return udpEchoAt(t, "127.0.0.1")
}

// udpEchoAt echoes UDP on a port of its own at host, or skips where host
// cannot be listened on.
func udpEchoAt(t *testing.T, host string) net.Addr {
	t.Helper()
	pc, err := net.ListenPacket("udp", host+":0")
	if err != nil {
		t.Skipf("listen on %s: %v", host, err)
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

// answerOverTCP serves DNS over TCP on a direct listener, answering the A
// questions in answers, with every address listed, and every other with
// nothing.
func answerOverTCP(answers map[string][]net.IP) func(net.Conn) {
	return func(c net.Conn) {
		for {
			var length [2]byte
			if _, err := io.ReadFull(c, length[:]); err != nil {
				return
			}
			buf := make([]byte, int(length[0])<<8|int(length[1]))
			if _, err := io.ReadFull(c, buf); err != nil {
				return
			}
			req := new(D.Msg)
			if req.Unpack(buf) != nil || len(req.Question) == 0 {
				return
			}
			reply := new(D.Msg)
			reply.SetReply(req)
			if q := req.Question[0]; q.Qtype == D.TypeA {
				for _, ip := range answers[strings.TrimSuffix(q.Name, ".")] {
					reply.Answer = append(reply.Answer, &D.A{Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: ip.To4()})
				}
			}
			b, err := reply.Pack()
			if err != nil {
				return
			}
			if _, err := c.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...)); err != nil {
				return
			}
		}
	}
}

// answerDNS serves the addresses by name over UDP on loopback, an empty answer
// for anything else, and returns its address.
func answerDNS(t *testing.T, answers map[string]string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			query := new(D.Msg)
			if query.Unpack(buf[:n]) != nil || len(query.Question) == 0 {
				continue
			}
			reply := new(D.Msg)
			reply.SetReply(query)
			q := query.Question[0]
			if address, ok := answers[q.Name]; ok && q.Qtype == D.TypeA {
				reply.Answer = append(reply.Answer, &D.A{
					Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
					A:   net.ParseIP(address).To4(),
				})
			}
			if packed, err := reply.Pack(); err == nil {
				_, _ = conn.WriteTo(packed, from)
			}
		}
	}()
	return conn.LocalAddr().String()
}
