//go:build !no_mihomo && (no_xray || !with_tun2socks)

package core

import (
	"fmt"

	mihomoCfg "github.com/metacubex/mihomo/config"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// Stubs: a build without the with_tun2socks tag (or without xray) runs mihomo on
// its native sing-tun everywhere and never links the bridge for it.
func (x *CoreController) mihomoUsesBridge(int) bool { return false }

// bridgeSetup is the bridge's per-session setup, which no build of this kind
// has.
type bridgeSetup struct{}

func (*bridgeSetup) adoptDirectBlocks(*mihomoCfg.Config, routing.Profile) {}

func mihomoBridgeInbound(*dnsconfig.Config, routing.Profile) (mihomoconfig.Inbound, *bridgeSetup) {
	return mihomoconfig.Inbound{}, nil
}

func (x *CoreController) mihomoStartBridge(*bridgeSetup, routing.Profile, dnsconfig.Config, int, int64) error {
	return fmt.Errorf("tun2socks bridge not linked in this build")
}

func (x *CoreController) mihomoStopBridge() {}
