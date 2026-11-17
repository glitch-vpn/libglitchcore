//go:build integration

package smoke

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// hotspotUnsupported is what the hotspot exports answer off Windows.
const hotspotUnsupported = 3

// Sharing switched off says so once and touches no connection, and a
// proxy-mode session beside it, which has no tunnel, moves nothing.
func TestSmoke_HotspotSharingOffBesideProxySession(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	result := core.SetHotspotSharing(`{"on":false,"blockWhileTunnelDown":true,"blockedClients":[]}`)
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
	const idle = `{"shared":"none","blocked":false,"error":"","restartOn":""}`
	if got := ev.waitFor(t, core.HotspotSharingEvent, 5*time.Second); got != idle {
		t.Fatalf("hotspot event = %s, want %s", got, idle)
	}

	upstream := startVlessServer(t)
	echo := echoBody(t, "198.51.100.77")
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Hotspot", testUUID, upstream)
	startProxyEngine(t, link, map[string]string{"probeUrl": echo.URL, "ipv4EchoUrl": echo.URL, "disableIPv6": "1"})
	ev.waitFor(t, core.EngineConnected, 30*time.Second)
	stopEngine(t, "xray")
	ev.waitFor(t, core.EngineDisconnected, 15*time.Second)
	if events := ev.all(core.HotspotSharingEvent); len(events) != 1 {
		t.Errorf("hotspot events = %v, want only the first", events)
	}
}
