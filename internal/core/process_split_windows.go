//go:build windows && (!no_xray || (!no_mihomo && !no_awg))

package core

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

const (
	ipUnicastIF   = 31
	ipv6UnicastIF = 31
)

// interfaceDialControl binds the socket to the named NIC (IP_UNICAST_IF /
// IPV6_UNICAST_IF) so a direct per-process dial egresses the physical interface
// instead of looping into the TUN. Both families are set; nil when ifaceName is
// empty/unresolvable. The IPv4 option takes the interface index in network byte order.
func interfaceDialControl(ifaceName string) func(network, address string, c syscall.RawConn) error {
	if ifaceName == "" {
		return nil
	}
	inf, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil
	}
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], uint32(inf.Index))
	v4Idx := int(*(*uint32)(unsafe.Pointer(&be[0]))) // network byte order for IP_UNICAST_IF
	v6Idx := inf.Index                               // host order for IPV6_UNICAST_IF
	return func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIF, v4Idx)
			_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, ipv6UnicastIF, v6Idx)
		})
	}
}
