//go:build !windows || !((!no_xray && !with_tun2socks) || (!no_mihomo && (no_xray || !with_tun2socks)))

package core

// startDesktopAdapterKeeper keeps nothing: only the sing-tun layer on Windows
// has an adapter worth keeping.
func startDesktopAdapterKeeper() *adapterKeeper { return nil }
