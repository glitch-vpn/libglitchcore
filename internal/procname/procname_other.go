//go:build !windows && !linux

package procname

import "net/netip"

func findProcessName(bool, netip.Addr, uint16) (string, error) {
	return "", ErrNotSupported
}
