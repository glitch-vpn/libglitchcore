//go:build windows && (!no_mihomo || (!no_xray && !with_tun2socks))

package core

import (
	"testing"

	tun "github.com/metacubex/sing-tun"
)

func TestSingTunTunnelTypeIsTheCores(t *testing.T) {
	if tun.TunnelType != "Glitch VPN" {
		t.Fatalf("sing-tun TunnelType %q, want %q", tun.TunnelType, "Glitch VPN")
	}
}
