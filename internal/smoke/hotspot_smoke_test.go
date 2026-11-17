//go:build integration

package smoke

import (
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// hotspotUnsupported is what the hotspot exports answer off Windows.
const hotspotUnsupported = 3

// Sharing turned on, with no hotspot on this machine, says "none" and touches
// no connection; a proxy-mode session beside it has no tunnel and moves
// nothing; turning it off says so again.
func TestSmoke_HotspotSharingOnBesideProxySession(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	const on = `{"on":true,"blockWhileTunnelDown":false,"blockedClients":[]}`
	result := core.SetHotspotSharing(on)
	if runtime.GOOS != "windows" {
		if result != hotspotUnsupported {
			t.Fatalf("SetHotspotSharing = %d, want %d off Windows", result, hotspotUnsupported)
		}
		if events := ev.all(core.HotspotSharingEvent); len(events) != 0 {
			t.Fatalf("events off Windows: %v", events)
		}
		return
	}
	if result != core.ResultSuccess {
		t.Fatalf("SetHotspotSharing = %d", result)
	}
	var first struct {
		Shared string `json:"shared"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.HotspotSharingEvent, 5*time.Second)), &first); err != nil {
		t.Fatal(err)
	}
	if first.Shared != "none" {
		t.Skip("a hotspot runs on this machine")
	}
	const off = `{"on":false,"blockWhileTunnelDown":false,"blockedClients":[]}`
	turnedOff := false
	t.Cleanup(func() {
		if !turnedOff {
			core.SetHotspotSharing(off)
		}
	})

	upstream := startVlessServer(t)
	echo := echoBody(t, "198.51.100.77")
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Hotspot", testUUID, upstream)
	startProxyEngine(t, link, map[string]string{"probeUrl": echo.URL, "ipv4EchoUrl": echo.URL, "disableIPv6": "1"})
	ev.waitFor(t, core.EngineConnected, 30*time.Second)
	stopEngine(t, "xray")
	ev.waitFor(t, core.EngineDisconnected, 15*time.Second)
	time.Sleep(2 * time.Second) // the worker's checks
	if events := ev.all(core.HotspotSharingEvent); len(events) != 1 {
		t.Errorf("hotspot events = %v, want only the first", events)
	}

	turnedOff = true
	if core.SetHotspotSharing(off) != core.ResultSuccess {
		t.Fatal("off was refused")
	}
	if !ev.waitForNew(t, core.HotspotSharingEvent, 1, 5*time.Second) {
		t.Error("off did not answer with the state")
	}
}
