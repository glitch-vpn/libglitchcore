//go:build with_gvisor && (!no_mihomo || (!no_xray && !with_tun2socks))

package core

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type idleTunHandler struct{}

func (idleTunHandler) PrepareConnection(string, M.Socksaddr, M.Socksaddr, tun.DirectRouteContext, time.Duration) (tun.DirectRouteDestination, error) {
	return nil, nil
}
func (idleTunHandler) NewConnection(context.Context, net.Conn, M.Metadata) error { return nil }
func (idleTunHandler) NewPacket(context.Context, netip.AddrPort, *buf.Buffer, M.Metadata, func(N.PacketConn) N.PacketWriter) {
}
func (idleTunHandler) NewError(context.Context, error) {}

// nativeStackSession is mihomo's native TUN stack, the one Android and Linux
// run, on a test link. Whatever admission the process holds judges its SYNs.
func nativeStackSession(t *testing.T) synSession {
	t.Helper()
	link := channel.New(8, 1500, "")
	s, err := tun.NewGVisorStack(link)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	forwarder := tun.NewTCPForwarder(t.Context(), s, idleTunHandler{})
	s.SetTransportProtocolHandler(header.TCPProtocolNumber, forwarder.HandlePacket)
	return synSession{
		send: func() {
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(synPacket(testDestination))})
			defer pkt.DecRef()
			link.InjectInbound(ipv6.ProtocolNumber, pkt)
		},
		answer: func(wait time.Duration) (byte, bool) {
			deadline := time.Now().Add(wait)
			for time.Now().Before(deadline) {
				if reply := link.Read(); reply != nil {
					defer reply.DecRef()
					return replyFlags(t, reply.ToView().AsSlice()), true
				}
				time.Sleep(10 * time.Millisecond)
			}
			return 0, false
		},
	}
}

// Mihomo's native TUN stack judges an IPv6 SYN by what the exit is known to
// carry, before any handshake.
func TestNativeTunStackJudgesIPv6FlowsByTheExit(t *testing.T) {
	checkStackJudgesByExit(t, func(t *testing.T, x *CoreController) synSession {
		setSingTunAdmission(x.admitTCPFlow)
		t.Cleanup(func() { setSingTunAdmission(nil) })
		return nativeStackSession(t)
	})
}

// The session's own arming and stop reach the stack, with no test installing
// the admission by hand.
func TestConfigureIPResolve_ArmsTheNativeTunStackAndStopDisarmsIt(t *testing.T) {
	x := &CoreController{}
	x.configureIPResolve(ipResolveConfig{enabled: true})
	armed := nativeStackSession(t)
	armed.send()
	if flags, answered := armed.answer(300 * time.Millisecond); answered {
		t.Fatalf("a session awaiting its echo answered an IPv6 SYN with flags %#x", flags)
	}
	x.exitIPv6.Store(exitIPv6Absent)
	armed.send()
	if flags, answered := armed.answer(time.Second); !answered || flags&tcpFlagRST == 0 {
		t.Fatalf("an exit without IPv6: flags %#x (answered %v), want a reset", flags, answered)
	}

	x.stopIPResolve()
	x.exitIPv6.Store(exitIPv6Absent) // were the hook left in place, this would reset the SYN
	stopped := nativeStackSession(t)
	stopped.send()
	if flags, answered := stopped.answer(time.Second); !answered || flags&tcpFlagSYN == 0 {
		t.Fatalf("after the session stopped: flags %#x (answered %v), want SYN+ACK", flags, answered)
	}
}
