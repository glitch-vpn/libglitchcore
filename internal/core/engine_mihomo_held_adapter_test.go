//go:build !no_mihomo && (no_xray || !with_tun2socks)

package core

import (
	"errors"
	"os"
	"testing"
	"time"
)

// mihomo's start takes the adapter through claimDesktopAdapter, so a name
// another process holds stops it with that reason as the start's error, not as
// "TUN listener failed to start (see mihomo logs)" after ApplyConfig. A start
// that took the gate directly would go on to create an adapter.
func TestMihomoStart_AHeldAdapterNameStopsTheStartWithTheReason(t *testing.T) {
	t.Cleanup(func() { applyGeoAssetsDir("") })
	k := startAdapterKeeper(&desktopAdapterGate, func() (keptAdapter, error) { return nil, errAdapterHeld })
	<-k.done
	desktopKeeper.Store(k)
	t.Cleanup(func() { desktopKeeper.Store(nil); k.close() })

	x := &CoreController{}
	mark, tun, done, err := x.beginStart(&x.mihomoSession, 0)
	if err != nil {
		t.Fatal(err)
	}
	// mihomo keeps cache.db open in its home, so the folder outlives the test.
	home, err := os.MkdirTemp("", "glitch-mihomo-test")
	if err != nil {
		t.Fatal(err)
	}
	startErr := x.mihomoStart([]string{"socks5://127.0.0.1:1080"}, tun, engineOpts{geoAssetsDir: home}, mark)
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
