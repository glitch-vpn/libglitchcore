//go:build !no_xray

package core

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

func init() { engine.SetICMPHandler(echoRequestDropper{}) }

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
