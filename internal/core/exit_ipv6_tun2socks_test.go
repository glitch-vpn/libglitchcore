//go:build !no_xray

package core

import (
	"net/netip"
	"testing"
	"time"
	_ "unsafe"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

type neverHandler struct{}

func (neverHandler) HandleTCP(adapter.TCPConn) {}
func (neverHandler) HandleUDP(adapter.UDPConn) {}

// The bridge's TUN stack, which xray and mihomo on Windows run, judges an IPv6
// SYN by what the exit is known to carry, before any handshake.
func TestBridgeStackJudgesIPv6FlowsByTheExit(t *testing.T) {
	checkStackJudgesByExit(t, func(t *testing.T, x *CoreController) synSession {
		link := channel.New(8, 1500, "")
		s, err := core.CreateStack(&core.Config{LinkEndpoint: link, TransportHandler: neverHandler{}, TCPAdmission: bridgeAdmission(x.admitTCPFlow)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { core.CloseStack(s) })
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
	})
}

// engineTCPAdmission is the admission the next engine start builds its stack
// with.
//
//go:linkname engineTCPAdmission github.com/xjasonlyu/tun2socks/v2/engine._tcpAdmission
var engineTCPAdmission core.TCPAdmission

// The engine clears its admission on every stop and on a failed start, so each
// session's bridge sets it again, and what it sets is the session's judgement.
func TestPrepareBridgeEngine_SetsTheSessionsTCPAdmissionEachTime(t *testing.T) {
	for session := 1; session <= 2; session++ {
		x := &CoreController{}
		x.exitIPv6.Store(exitIPv6Absent)
		prepareBridgeEngine(&engine.Key{}, x.admitTCPFlow)
		if engineTCPAdmission == nil {
			t.Fatalf("session %d: no TCP admission set", session)
		}
		if got := engineTCPAdmission(netip.AddrPortFrom(testDestination, 443)); got != core.TCPReset {
			t.Fatalf("session %d: verdict for IPv6 through an exit without it = %d, want reset", session, got)
		}
		if err := engine.Stop(); err != nil {
			t.Fatal(err)
		}
		if engineTCPAdmission != nil {
			t.Fatalf("session %d: the engine kept its TCP admission after a stop", session)
		}
	}
}
