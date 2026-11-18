//go:build !no_mihomo && (no_xray || !with_tun2socks)

package core

import (
	"errors"
	"testing"
	"time"
)

// mihomo's start takes the adapter through claimDesktopAdapter, before it
// builds a config, so a name another process holds stops it with that reason as
// the start's error, not as "TUN listener failed to start (see mihomo logs)"
// after ApplyConfig, and without mihomo logging anything. A start that took the
// gate directly would go on to build a config and create an adapter.
func TestMihomoStart_AHeldAdapterNameStopsTheStartWithTheReason(t *testing.T) {
	k := startAdapterKeeper(&desktopAdapterGate, func() (keptAdapter, error) { return nil, errAdapterHeld })
	<-k.done
	desktopKeeper.Store(k)
	t.Cleanup(func() { desktopKeeper.Store(nil); k.close() })

	x := &CoreController{}
	mark, tun, done, err := x.beginStart(&x.mihomoSession, 0)
	if err != nil {
		t.Fatal(err)
	}
	startErr := x.mihomoStart([]string{"socks5://127.0.0.1:1080"}, tun, engineOpts{}, mark)
	done()
	if !errors.Is(startErr, errAdapterHeld) {
		t.Fatalf("start = %v; want the held reason", startErr)
	}
	release, err := desktopAdapterGate.claim(time.Second)
	if err != nil {
		t.Fatalf("the gate stayed held after the refusal: %v", err)
	}
	release()
}
