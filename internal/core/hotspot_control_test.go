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

// resetPrepareFlight forgets an earlier test's repair.
func resetPrepareFlight() {
	prepareFlight.mu.Lock()
	prepareFlight.token, prepareFlight.running, prepareFlight.finished, prepareFlight.result = "", false, false, 0
	prepareFlight.mu.Unlock()
}

// replacePrepare makes the repair wait for release, counting its runs.
func replacePrepare(t *testing.T, result int32) (release func(), runs func() int) {
	t.Helper()
	resetPrepareFlight()
	gate := make(chan struct{})
	var releaseOnce sync.Once
	release = func() { releaseOnce.Do(func() { close(gate) }) }
	t.Cleanup(release)
	var mu sync.Mutex
	count := 0
	previous := prepareHotspotFunc
	prepareHotspotFunc = func() int32 {
		mu.Lock()
		count++
		mu.Unlock()
		<-gate
		return result
	}
	t.Cleanup(func() { prepareHotspotFunc = previous })
	return release, func() int {
		mu.Lock()
		defer mu.Unlock()
		return count
	}
}

func awaitPrepareAnswer(t *testing.T, token string) int32 {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if done, result := pollPrepareHotspot(token); done {
			return result
		}
		select {
		case <-deadline:
			t.Fatal("the repair never finished")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestPollPrepareHotspotRunsOnceOffTheCaller(t *testing.T) {
	release, runs := replacePrepare(t, hotspotResultRunning)

	for i := 0; i < 3; i++ {
		if done, _ := pollPrepareHotspot("a"); done {
			t.Fatal("a repair that has not finished answered done")
		}
	}
	release()
	if result := awaitPrepareAnswer(t, "a"); result != hotspotResultRunning {
		t.Errorf("result = %d", result)
	}
	if got := runs(); got != 1 {
		t.Errorf("the repair ran %d times, want 1", got)
	}
}

// A finished repair's answer is its starter's alone: a second caller does not
// receive it, however soon it asks, and starts its own repair.
func TestPollPrepareHotspotAnswersOnlyTheSequenceThatStarted(t *testing.T) {
	release, runs := replacePrepare(t, hotspotResultRunning)
	release()

	if done, _ := pollPrepareHotspot("first"); done {
		t.Fatal("answered before the repair ran")
	}
	deadline := time.After(5 * time.Second)
	for {
		prepareFlight.mu.Lock()
		finished := prepareFlight.finished
		prepareFlight.mu.Unlock()
		if finished {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the repair never finished")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// The first caller never came back. Another does not get its answer.
	if done, _ := pollPrepareHotspot("second"); done {
		t.Fatal("the second caller was given the first one's answer")
	}
	if result := awaitPrepareAnswer(t, "second"); result != hotspotResultRunning {
		t.Errorf("result = %d", result)
	}
	if got := runs(); got != 2 {
		t.Errorf("the repair ran %d times, want 2: one per sequence", got)
	}
}

// A caller that finds another's repair under way waits for it; it does not
// start a second one beside it.
func TestPollPrepareHotspotDoesNotStartASecondRepairBesideTheFirst(t *testing.T) {
	release, runs := replacePrepare(t, ResultSuccess)

	pollPrepareHotspot("first")
	for i := 0; i < 3; i++ {
		if done, _ := pollPrepareHotspot("second"); done {
			t.Fatal("answered while the first repair runs")
		}
	}
	if got := runs(); got > 1 {
		t.Errorf("%d repairs started at once", got)
	}
	release()
	awaitPrepareAnswer(t, "first")
	if result := awaitPrepareAnswer(t, "second"); result != ResultSuccess {
		t.Errorf("result = %d", result)
	}
}
