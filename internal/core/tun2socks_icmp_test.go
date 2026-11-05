//go:build !no_xray

package core

import (
	"context"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	t2score "github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
)

type nopTransportHandler struct{}

func (nopTransportHandler) HandleTCP(adapter.TCPConn) {}
func (nopTransportHandler) HandleUDP(adapter.UDPConn) {}

// echoRequestV4 is an echo request from a device on the tunnel to an address
// the stack does not own.
func echoRequestV4() *stack.PacketBuffer {
	const payload = 8
	frame := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize+payload)
	ip := header.IPv4(frame)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(frame)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
		DstAddr:     tcpip.AddrFrom4([4]byte{1, 1, 1, 1}),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	icmp := header.ICMPv4(frame[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4Echo)
	icmp.SetIdent(7)
	icmp.SetSequence(1)
	icmp.SetChecksum(^checksum.Checksum(icmp, 0))
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
}

// echoRequestV6 is the IPv6 counterpart of echoRequestV4.
func echoRequestV6() *stack.PacketBuffer {
	src := tcpip.AddrFrom16([16]byte{0xfd, 15: 2})
	dst := tcpip.AddrFrom16([16]byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 15: 0x11})
	frame := make([]byte, header.IPv6MinimumSize+header.ICMPv6EchoMinimumSize)
	header.IPv6(frame).Encode(&header.IPv6Fields{
		PayloadLength:     header.ICMPv6EchoMinimumSize,
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	icmp := header.ICMPv6(frame[header.IPv6MinimumSize:])
	icmp.SetType(header.ICMPv6EchoRequest)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: src, Dst: dst}))
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
}

// pingThroughBridgeStack injects an echo request and reports whether the
// stack sent anything back on the device.
func pingThroughBridgeStack(t *testing.T, network tcpip.NetworkProtocolNumber, handler adapter.NetworkHandler) bool {
	t.Helper()
	device := channel.New(16, 1500, "")
	s, err := t2score.CreateStack(&t2score.Config{
		LinkEndpoint:     device,
		TransportHandler: nopTransportHandler{},
		ICMPHandler:      handler,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { t2score.CloseStack(s) })

	pkt := echoRequestV4()
	if network == ipv6.ProtocolNumber {
		pkt = echoRequestV6()
	}
	defer pkt.DecRef()
	device.InjectInbound(network, pkt)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	reply := device.ReadContext(ctx)
	if reply == nil {
		return false
	}
	reply.DecRef()
	return true
}

func TestBridgeStack_AnswersAnEchoRequestUnlessItIsDropped(t *testing.T) {
	for name, network := range map[string]tcpip.NetworkProtocolNumber{"IPv4": ipv4.ProtocolNumber, "IPv6": ipv6.ProtocolNumber} {
		t.Run(name, func(t *testing.T) {
			if !pingThroughBridgeStack(t, network, nil) {
				t.Fatal("the stack's own handler did not answer the echo request: the drop below proves nothing")
			}
			if pingThroughBridgeStack(t, network, echoRequestDropper{}) {
				t.Fatal("the bridge answered an echo request from inside the tunnel")
			}
		})
	}
}
