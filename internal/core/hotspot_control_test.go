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

	sharing := newHotspotSharing(os, func(payload string) { x.emitStatus(HotspotSharingEvent, payload) }, tunnelPhase(x.enginePhase.Load()))
	sharing.useWorker(0)
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

	x.emitStatus(EngineDisconnecting, "[Xray] Disconnecting")
	os.mu.Lock()
	os.tunnel = 0
	os.mu.Unlock()
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

// The controller tracks the engine's phase whether or not a hotspot asked yet,
// so an order created later starts from it.
func TestControllerTracksTheEnginePhaseForALaterHotspot(t *testing.T) {
	x := &CoreController{}
	x.emitStatus(EngineConnecting, "[Xray] Connecting")
	x.emitStatus(EngineConnected, "[Xray] Connected")
	x.emitStatus(StatsEvent, "{}")
	if got := tunnelPhase(x.enginePhase.Load()); got != tunnelUp {
		t.Fatalf("phase = %v, want up", got)
	}

	os := newFakeHotspotOS()
	os.tunnel = testTunnel
	os.present[testTunnel] = true
	var payloads []string
	sharing := newHotspotSharing(os, func(payload string) { payloads = append(payloads, payload) }, tunnelPhase(x.enginePhase.Load()))
	if err := sharing.set(hotspotSharingRequest{On: true}); err != nil {
		t.Fatal(err)
	}
	if os.public != testTunnel || !os.forwarding[testHotspot] {
		t.Errorf("a hotspot turned on under a running tunnel is on ICS public %d, forwarding %t", os.public, os.forwarding[testHotspot])
	}
}

func TestPollPrepareHotspotRunsOnceOffTheCaller(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	previous := prepareHotspotFunc
	prepareHotspotFunc = func() int32 {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release
		return hotspotResultRunning
	}
	t.Cleanup(func() { prepareHotspotFunc = previous })

	for i := 0; i < 3; i++ {
		if done, _ := pollPrepareHotspot(); done {
			t.Fatal("a repair that has not finished answered done")
		}
	}
	close(release)
	deadline := time.After(5 * time.Second)
	for {
		if done, result := pollPrepareHotspot(); done {
			if result != hotspotResultRunning {
				t.Errorf("result = %d", result)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("the repair never finished")
		case <-time.After(10 * time.Millisecond):
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("the repair ran %d times, want 1", calls)
	}
}
