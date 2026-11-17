//go:build windows && !no_xray && with_tun2socks

package core

import (
	"testing"

	wintunTun "golang.zx2c4.com/wireguard/tun"
)

func TestBridgeAdapterKeepsTheDesktopIdentity(t *testing.T) {
	if wintunTun.WintunTunnelType != "Glitch VPN" {
		t.Fatalf("Wintun tunnel type %q, want %q", wintunTun.WintunTunnelType, "Glitch VPN")
	}
	// md5("wintun" + "GlitchVPN"), the GUID sing-tun derives for the same name.
	const want = "{A7DD3E51-E109-8B19-9263-C9109EB82BF5}"
	if got := wintunTun.WintunStaticRequestedGUID.String(); got != want {
		t.Fatalf("adapter GUID %s, want %s", got, want)
	}
}
