//go:build !no_xray && !with_tun2socks && with_gvisor

package core

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
)

// stalledSocks accepts and never answers: a proxy that is slow to handshake.
func stalledSocks(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
	})
	return l.Addr().(*net.TCPAddr).Port
}

func udpDatagramPacket(src, dst netip.AddrPort, payload []byte) []byte {
	b := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(b)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber),
		SrcAddr: tcpip.AddrFrom4(src.Addr().As4()), DstAddr: tcpip.AddrFrom4(dst.Addr().As4())})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(b[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: src.Port(), DstPort: dst.Port(), Length: uint16(header.UDPMinimumSize + len(payload))})
	copy(u.Payload(), payload)
	return b
}

// requireSYNAnsweredBehind injects burst datagrams of one UDP flow and then
// another app's TCP SYN into a stack running h, and requires the SYN's answer:
// the stack hands both over on one goroutine, which never waits on a flow.
func requireSYNAnsweredBehind(t *testing.T, h *xrayTunHandler, burst int) {
	t.Helper()
	link := channel.New(512, 1500, "")
	session, err := startXrayTunStack(channelTun{ep: link}, tunTestOptions(1500), h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.close)
	src := netip.AddrPortFrom(tunTestApp, 50000)
	dst := netip.AddrPortFrom(tunTestDest, 5000)
	payload := make([]byte, 1400)
	inject := func(family tcpip.NetworkProtocolNumber, packet []byte) {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		link.InjectInbound(family, pkt)
		pkt.DecRef()
	}
	go func() {
		for i := 0; i < burst; i++ {
			inject(ipv4.ProtocolNumber, udpDatagramPacket(src, dst, payload))
		}
		inject(ipv6.ProtocolNumber, synPacket(testDestination))
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if reply := link.Read(); reply != nil {
			v := reply.ToView().AsSlice()
			answered := len(v) >= 54 && v[0]>>4 == 6 && v[6] == 6 && v[40+13]&tcpFlagSYN != 0
			reply.DecRef()
			if answered {
				return
			}
			continue
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("another app's SYN went unanswered for 5s")
}

func newHOLHandler(t *testing.T, prof routing.Profile, socksPort int) *xrayTunHandler {
	t.Helper()
	inst := startTunInstance(t, prof, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, socksPort, nil)
	x := &CoreController{}
	sniffing, err := xrayconfig.AppSniffing(true, false)
	if err != nil {
		t.Fatal(err)
	}
	h, err := x.newXrayTunHandler(xrayTunParams{instance: inst.Instance, sniffing: sniffing, routing: prof, mark: x.sessionGen.Load()})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// A burst of datagrams to a flow whose proxy has not read yet, more than the
// pipe in front of a proxy holds on any platform.
func TestXrayTun_AStalledUDPFlowDoesNotHoldUpOtherFlows(t *testing.T) {
	h := newHOLHandler(t, routing.Profile{Mode: routing.ModeProxyAll}, stalledSocks(t))
	requireSYNAnsweredBehind(t, h, 1000)
}

// The process lookup of a new UDP flow runs off the stack's goroutine too.
func TestXrayTun_ASlowProcessLookupDoesNotHoldUpOtherFlows(t *testing.T) {
	prof := routing.Profile{Mode: routing.ModeProxyAll, Tiers: []routing.Tier{{Direct: []string{"process:app.exe"}}}}
	h := newHOLHandler(t, prof, stalledSocks(t))
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h.split.processName = func(string, netip.AddrPort) (string, error) {
		<-release
		return "", errors.New("slow")
	}
	requireSYNAnsweredBehind(t, h, 1)
}
