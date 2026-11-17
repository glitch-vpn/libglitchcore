//go:build !no_mihomo && !no_xray

package core

import (
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/component/process"
	C "github.com/metacubex/mihomo/constant"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
	D "github.com/miekg/dns"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// directResolver answers over TCP at host from answer, which gets every name
// asked and its record type.
func directResolver(t *testing.T, host net.IP, answer func(name string, qtype uint16) ([]D.RR, time.Duration)) string {
	t.Helper()
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	listenDirect(t, host, port, nil, func(c net.Conn) {
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
			q := req.Question[0]
			records, hold := answer(strings.TrimSuffix(q.Name, "."), q.Qtype)
			reply := new(D.Msg)
			reply.SetReply(req)
			reply.Answer = records
			b, err := reply.Pack()
			if err != nil {
				return
			}
			go func() {
				time.Sleep(hold)
				_, _ = c.Write(append([]byte{byte(len(b) >> 8), byte(len(b))}, b...))
			}()
		}
	})
	return "tcp://" + net.JoinHostPort(host.String(), strconv.Itoa(port))
}

// listenCounting counts the connections made at host:port, echoing them back.
func listenCounting(t *testing.T, host string, port int) *atomic.Int32 {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Skipf("listen on %s: %v", host, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var count atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return &count
}

// startNativeDirectApp starts mihomo through the production wiring on the
// native TUN's config, with the listener off and its tunnel fed by hand, for a
// profile that sends direct.exe direct and blocks an address.
func startNativeDirectApp(t *testing.T, prof routing.Profile, directResolverAddress string) {
	t.Helper()
	skipWhereMihomoRaces(t)
	mihomoTestHome(t)
	t.Cleanup(mihomoTeardown)
	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"127.0.0.1:1"}, DirectServers: []string{directResolverAddress}}
	inbound := mihomoconfig.Inbound{Tun: mihomoTunInbound(dns, -1)}
	cfg, err := mihomoconfig.BuildConfig([]string{vlessTestLink}, inbound, mihomoconfig.Options{}, prof)
	if err != nil {
		t.Fatal(err)
	}
	cfg.General.Tun.Enable = false
	cfg.General.FindProcessMode = process.FindProcessOff
	target := mihomoconfig.Target([]string{vlessTestLink})
	recorder, err := adapter.ParseProxy(map[string]any{"name": target, "type": "socks5", "server": "127.0.0.1", "port": socksRecorder(t, make(chan string, 8))})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Proxies[target] = recorder
	applyMihomoConfig(cfg, inbound, false, prof)
}

var nativeDirectAppProfile = routing.Profile{
	Mode:  routing.ModeProxyAll,
	Tiers: []routing.Tier{{Direct: []string{"process:direct.exe"}}, {Block: []string{"127.0.0.5/32"}}},
}

// A name whose answer changes at every lookup is looked up once: the flow is
// dialled at the address the blocks were checked against, not at one a second
// lookup finds.
func TestMihomoNativeTun_ProcessDirectTCPFlowDialsTheCheckedAddressWhenTheAnswerChanges(t *testing.T) {
	var lookups atomic.Int32
	answers := []net.IP{net.IPv4(127, 0, 0, 6), net.IPv4(127, 0, 0, 5)}
	server := directResolver(t, net.IPv4(127, 0, 0, 2), func(name string, qtype uint16) ([]D.RR, time.Duration) {
		if name != "rotating.test" || qtype != D.TypeA {
			return nil, 0
		}
		ip := answers[int(lookups.Add(1)-1)%len(answers)]
		return []D.RR{&D.A{Hdr: D.RR_Header{Name: name + ".", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 0}, A: ip.To4()}}, 0
	})
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	open := listenCounting(t, "127.0.0.6", port)
	blocked := listenCounting(t, "127.0.0.5", port)
	startNativeDirectApp(t, nativeDirectAppProfile, server)

	for round := 0; round < 3; round++ {
		fake := fakeIPFor(t, "rotating.test")
		lookups.Store(0)
		openBefore := open.Load()
		nativeTunFlow(t, fake, port, "direct.exe")
		deadline := time.Now().Add(5 * time.Second)
		for open.Load() == openBefore && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if open.Load() == openBefore {
			t.Fatalf("round %d: the flow was not dialled at the address that passed the blocks", round)
		}
		if n := blocked.Load(); n != 0 {
			t.Fatalf("round %d: the blocked address took %d connections", round, n)
		}
		if n := lookups.Load(); n != 1 {
			t.Fatalf("round %d: the name was looked up %d times, want once", round, n)
		}
	}
}

// An address the second record type answers late is not left out of the check
// by the wait the first one allowed: nothing listens at the address that was
// checked, and the flow does not fall through to one that was not.
func TestMihomoNativeTun_ProcessDirectTCPFlowNeverDialsAnAddressItDidNotCheck(t *testing.T) {
	server := directResolver(t, net.IPv4(127, 0, 0, 2), func(name string, qtype uint16) ([]D.RR, time.Duration) {
		header := D.RR_Header{Name: name + ".", Class: D.ClassINET, Ttl: 0}
		switch {
		case name != "late-v6.test":
			return nil, 0
		case qtype == D.TypeA:
			header.Rrtype = D.TypeA
			return []D.RR{&D.A{Hdr: header, A: net.IPv4(127, 0, 0, 6).To4()}}, 0
		case qtype == D.TypeAAAA:
			header.Rrtype = D.TypeAAAA
			return []D.RR{&D.AAAA{Hdr: header, AAAA: net.IPv6loopback}}, 400 * time.Millisecond
		}
		return nil, 0
	})
	prof := routing.Profile{
		Mode:  routing.ModeProxyAll,
		Tiers: []routing.Tier{{Block: []string{"::1/128"}, Direct: []string{"process:direct.exe"}}},
	}
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	blocked := listenCounting(t, "::1", port)
	startNativeDirectApp(t, prof, server)

	nativeTunFlow(t, fakeIPFor(t, "late-v6.test"), port, "direct.exe")
	time.Sleep(1500 * time.Millisecond)
	if n := blocked.Load(); n != 0 {
		t.Errorf("the blocked address took %d connections", n)
	}
}

// mihomoDatagram is a datagram the TUN hands mihomo's tunnel.
type mihomoDatagram struct {
	data []byte
	src  *net.UDPAddr
}

func (p *mihomoDatagram) Data() []byte                                { return p.data }
func (p *mihomoDatagram) WriteBack(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (p *mihomoDatagram) Drop()                                       {}
func (p *mihomoDatagram) LocalAddr() net.Addr                         { return p.src }

// listenCountingUDP counts the datagrams that reach host:port.
func listenCountingUDP(t *testing.T, host string, port int) *atomic.Int32 {
	t.Helper()
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		t.Skipf("listen udp on %s: %v", host, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	var count atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			count.Add(1)
		}
	}()
	return &count
}

// The datagrams of a process-direct app to a name whose answer changes at every
// lookup all reach the address the blocks were checked against: the name is
// looked up once for the flow.
func TestMihomoNativeTun_ProcessDirectUDPFlowSendsToTheCheckedAddressWhenTheAnswerChanges(t *testing.T) {
	var lookups atomic.Int32
	answers := []net.IP{net.IPv4(127, 0, 0, 6), net.IPv4(127, 0, 0, 5)}
	server := directResolver(t, net.IPv4(127, 0, 0, 2), func(name string, qtype uint16) ([]D.RR, time.Duration) {
		if name != "rotating-udp.test" || qtype != D.TypeA {
			return nil, 0
		}
		ip := answers[int(lookups.Add(1)-1)%len(answers)]
		return []D.RR{&D.A{Hdr: D.RR_Header{Name: name + ".", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 0}, A: ip.To4()}}, 0
	})
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	open := listenCountingUDP(t, "127.0.0.6", port)
	blocked := listenCountingUDP(t, "127.0.0.5", port)
	startNativeDirectApp(t, nativeDirectAppProfile, server)

	const datagrams = 5
	for round := 0; round < 3; round++ {
		fake := fakeIPFor(t, "rotating-udp.test")
		lookups.Store(0)
		openBefore := open.Load()
		src := &net.UDPAddr{IP: net.IPv4(198, 18, 0, 1), Port: 43000 + round}
		for i := 0; i < datagrams; i++ {
			metadata := &C.Metadata{NetWork: C.UDP, Type: C.TUN, SrcIP: netip.MustParseAddr("198.18.0.1"), SrcPort: uint16(src.Port), DstPort: uint16(port), Process: "direct.exe"}
			metadata.DstIP, _ = netip.AddrFromSlice(fake.To4())
			mihomoTunnel.Tunnel.HandleUDPPacket(&mihomoDatagram{data: []byte("datagram"), src: src}, metadata)
			time.Sleep(100 * time.Millisecond)
		}
		time.Sleep(300 * time.Millisecond)
		if n := blocked.Load(); n != 0 {
			t.Fatalf("round %d: the blocked address took %d datagrams", round, n)
		}
		if n := open.Load() - openBefore; n != datagrams {
			t.Fatalf("round %d: %d of %d datagrams reached the checked address", round, n, datagrams)
		}
		if n := lookups.Load(); n != 1 {
			t.Fatalf("round %d: the name was looked up %d times, want once", round, n)
		}
	}
}
