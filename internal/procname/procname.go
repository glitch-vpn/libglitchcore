// Package procname resolves which local process owns a socket (by source address).
// Clean-room replacement for mihomo's GPL component/process.
package procname

import (
	"errors"
	"net/netip"
	"strings"
)

var (
	ErrNotSupported = errors.New("process lookup not supported on this platform")
	ErrNotFound     = errors.New("no process owns this connection")
)

// FindProcessName: network is "tcp"/"udp" (v4/v6 suffixes ok).
func FindProcessName(network string, src netip.Addr, srcPort int) (string, error) {
	return findProcessName(strings.HasPrefix(network, "tcp"), src.Unmap(), uint16(srcPort))
}
