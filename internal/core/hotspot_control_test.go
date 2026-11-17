package core

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// A controller with a hotspot order over a fake OS answers the engine's
// lifecycle events by itself, and its event reaches the status sink.
func TestControllerMovesTheHotspotWithEngineEvents(t *testing.T) {
	os := newFakeHotspotOS()
	x := &CoreController{}
	var mu sync.Mutex
	var received []hotspotSharingEvent
	arrived := make(chan struct{}, 16)
	setStatusSink(func(code int32, message string) {
		if code != HotspotSharingEvent {
			return
		}
		var event hotspotSharingEvent
		if err := json.Unmarshal([]byte(message), &event); err != nil {
			t.Errorf("event %q is not JSON: %v", message, err)
			return
		}
		mu.Lock()
		received = append(received, event)
		mu.Unlock()
		arrived <- struct{}{}
	})
	t.Cleanup(func() { setStatusSink(nil) })

	sharing := newHotspotSharing(os, func(payload string) { x.emitStatus(HotspotSharingEvent, payload) })
	sharing.start(0)
	t.Cleanup(sharing.close)
	x.hotspot.Store(sharing)

	waitEvent := func(want hotspotSharingEvent) {
		t.Helper()
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatalf("no event; wanted %+v", want)
		}
		mu.Lock()
		defer mu.Unlock()
		if got := received[len(received)-1]; got != want {
			t.Fatalf("event = %+v, want %+v", got, want)
		}
	}

	if err := sharing.set(hotspotSharingRequest{On: true, BlockWhileTunnelDown: true}); err != nil {
		t.Fatal(err)
	}
	waitEvent(hotspotSharingEvent{Shared: hotspotSharedWiFi, Blocked: true})

	os.mu.Lock()
	os.tunnel = testTunnel
	os.mu.Unlock()
	x.emitStatus(EngineConnected, "[Xray] Connected")
	waitEvent(hotspotSharingEvent{Shared: hotspotSharedTunnel})

	x.emitStatus(EngineDisconnected, "[Xray] Disconnected")
	waitEvent(hotspotSharingEvent{Shared: hotspotSharedTunnel, Blocked: true})

	x.emitStatus(StatsEvent, "{}")
	select {
	case <-arrived:
		t.Error("a stats event moved the hotspot")
	case <-time.After(100 * time.Millisecond):
	}

	x.replayHotspot()
	waitEvent(hotspotSharingEvent{Shared: hotspotSharedTunnel, Blocked: true})
}

func TestSetHotspotSharingRejectsABadRequest(t *testing.T) {
	if !hotspotSupported {
		t.Skip("answers unsupported before it reads the request")
	}
	previous := globalController
	globalController = &CoreController{}
	t.Cleanup(func() { globalController = previous })
	for _, request := range []string{`{`, `{"on":true,"blockedClients":["fe80::1"]}`} {
		if got := SetHotspotSharing(request); got != hotspotResultBadRequest {
			t.Errorf("SetHotspotSharing(%s) = %d, want %d", request, got, hotspotResultBadRequest)
		}
	}
}
