//go:build windows && !no_xray && with_tun2socks

package core

import (
	wintunTun "golang.zx2c4.com/wireguard/tun"
)

// The bridge's Wintun binding sets the adapter's description ("tun2socks
// Tunnel") in its init and lets Wintun draw a GUID at random; the adapter's
// name comes from the device URI (tun://GlitchVPN). This init runs after it
// and gives the adapter sing-tun's description and GUID.
func init() {
	wintunTun.WintunTunnelType = desktopTunnelType
	wintunTun.WintunStaticRequestedGUID = adapterGUID(desktopAdapterName)
}
