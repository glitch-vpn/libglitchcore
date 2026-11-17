//go:build !no_xray && !with_tun2socks

package core

// tunLayerState is what the sing-tun layer holds for a session.
type tunLayerState struct {
	xrayTun *xrayTunSession
}
