//go:build windows && (!no_mihomo || (!no_xray && !with_tun2socks))

package core

import tun "github.com/metacubex/sing-tun"

// mihomo's listener sets this global to its own name in its init. A package
// init runs after the init of every package it imports, so this one wins in
// any build that links mihomo, and sets it in one that does not.
func init() {
	tun.TunnelType = desktopTunnelType
}
