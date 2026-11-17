//go:build !no_xray && with_tun2socks

package core

import (
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	t2score "github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

// prepareBridgeEngine loads a session's key, its ICMP handler and its TCP
// admission together: tun2socks clears the handlers on every stop and on a
// failed start, so one set earlier does not reach the next session.
func prepareBridgeEngine(key *engine.Key, admit func(netip.AddrPort) tcpVerdict) {
	engine.SetICMPHandler(echoRequestDropper{})
	engine.SetTCPAdmission(bridgeAdmission(admit))
	engine.Insert(key)
}

func bridgeAdmission(admit func(netip.AddrPort) tcpVerdict) t2score.TCPAdmission {
	if admit == nil {
		return nil
	}
	return func(destination netip.AddrPort) t2score.TCPVerdict {
		switch admit(destination) {
		case tcpReset:
			return t2score.TCPReset
		case tcpDrop:
			return t2score.TCPDrop
		}
		return t2score.TCPAdmit
	}
}

// echoRequestDropper takes every ICMP echo request for itself and never
// answers it. Left to the stack, the bridge replies to a ping from the device
// as though the exit had, and the latency it shows crossed no tunnel.
type echoRequestDropper struct{}

func (echoRequestDropper) HandlePacket(p adapter.Packet) bool {
	return isEchoRequest(p.Buffer().NetworkProtocolNumber, p.Buffer().TransportHeader().Slice())
}

func isEchoRequest(network tcpip.NetworkProtocolNumber, transport []byte) bool {
	switch network {
	case ipv4.ProtocolNumber:
		h := header.ICMPv4(transport)
		return len(h) >= header.ICMPv4MinimumSize && h.Type() == header.ICMPv4Echo
	case ipv6.ProtocolNumber:
		h := header.ICMPv6(transport)
		return len(h) >= header.ICMPv6MinimumSize && h.Type() == header.ICMPv6EchoRequest
	}
	return false
}
