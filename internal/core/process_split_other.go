//go:build !windows && (!no_xray || (!no_mihomo && !no_awg))

package core

import "syscall"

// interfaceDialControl is a no-op off Windows: the TUN default-route loop that
// requires IP_UNICAST_IF binding is Windows-specific (Android uses VpnService
// app exclusion; Linux binds differently).
func interfaceDialControl(ifaceName string) func(network, address string, c syscall.RawConn) error {
	return nil
}
