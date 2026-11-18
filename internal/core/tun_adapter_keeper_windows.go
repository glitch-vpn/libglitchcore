//go:build windows && ((!no_xray && !with_tun2socks) || (!no_mihomo && (no_xray || !with_tun2socks)))

package core

import (
	"errors"

	tun "github.com/metacubex/sing-tun"
	"golang.org/x/sys/windows"
)

// startDesktopAdapterKeeper keeps the adapter sing-tun creates, under the name
// and identity every session of both engines uses. Both reach the fork's New,
// which starts its session on the kept adapter. It is built only where sing-tun
// drives the TUN: the tun2socks bridge creates the adapter itself, and would
// find the kept one in its way.
func startDesktopAdapterKeeper() *adapterKeeper {
	if useServiceIPC || !windows.GetCurrentProcessToken().IsElevated() {
		return nil
	}
	return startAdapterKeeper(&desktopAdapterGate, func() (keptAdapter, error) {
		adapter, err := tun.KeepAdapter(desktopAdapterName, desktopTunnelType)
		if errors.Is(err, tun.ErrAdapterHeld) {
			return nil, errAdapterHeld
		}
		if err != nil {
			return nil, err
		}
		return adapter, nil
	})
}
