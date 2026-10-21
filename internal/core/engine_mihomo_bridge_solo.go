//go:build !no_mihomo && no_xray && no_awg

package core

import (
	"fmt"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// Stubs: mihomo-only builds never link tun2socks (native sing-tun everywhere).
func (x *CoreController) mihomoUsesBridge(int) bool { return false }

func mihomoBridgeInbound(*dnsconfig.Config, routing.Profile) (mihomoconfig.Inbound, *bridgeSetup) {
	return mihomoconfig.Inbound{}, nil
}

func (x *CoreController) mihomoStartBridge(*bridgeSetup, routing.Profile, dnsconfig.Config, int, int64) error {
	return fmt.Errorf("tun2socks bridge not linked in this build")
}

func (x *CoreController) mihomoStopBridge() {}
