package core

import (
	"encoding/json"
	"errors"
	"math"
	"sync"
	"testing"
	"time"
)

// hotspotEvents collects the sharing events the status sink receives.
type hotspotEvents struct {
	t        *testing.T
	mu       sync.Mutex
	received []hotspotSharingEvent
	arrived  chan struct{}
}

func captureHotspotEvents(t *testing.T) *hotspotEvents {
	t.Helper()
	events := &hotspotEvents{t: t, arrived: make(chan struct{}, 64)}
	setStatusSink(func(code int32, message string) {
		if code != HotspotSharingEvent {
			return
		}
		var event hotspotSharingEvent
		if err := json.Unmarshal([]byte(message), &event); err != nil {
			t.Errorf("event %q is not JSON: %v", message, err)
			return
		}
		events.mu.Lock()
		events.received = append(events.received, event)
		events.mu.Unlock()
		events.arrived <- struct{}{}
	})
	t.Cleanup(func() { setStatusSink(nil) })
	return events
}

func (e *hotspotEvents) wait(want hotspotSharingEvent) {
	e.t.Helper()
	select {
	case <-e.arrived:
	case <-time.After(5 * time.Second):
		e.t.Fatalf("no event; wanted %+v", want)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if got := e.received[len(e.received)-1]; got != want {
		e.t.Fatalf("event = %+v, want %+v", got, want)
	}
}

func (e *hotspotEvents) expectNone(within time.Duration) bool {
	select {
	case <-e.arrived:
		return false
	case <-time.After(within):
		return true
	}
}

// A controller with a hotspot order over a fake OS answers the engine's
// lifecycle events by itself, and its event reaches the status sink.
func TestControllerMovesTheHotspotWithEngineEvents(t *testing.T) {
	os := newFakeHotspotOS()
	x := &CoreController{}
	events := captureHotspotEvents(t)

	sharing := newHotspotSharing(os, func(payload string) { x.emitStatus(HotspotSharingEvent, payload) }, tunnelPhase(x.enginePhase.Load()))
	sharing.useWorker(0)
	t.Cleanup(sharing.close)
	x.hotspot.Store(sharing)

	if err := sharing.set(hotspotSharingRequest{On: true, BlockWhileTunnelDown: true}); err != nil {
		t.Fatal(err)
	}
	events.wait(hotspotSharingEvent{Shared: hotspotSharedNone, Blocked: true})

	os.mu.Lock()
	os.tunnel = testTunnel
	os.mu.Unlock()
	x.emitStatus(EngineConnected, "[Xray] Connected")
	events.wait(hotspotSharingEvent{Shared: hotspotSharedTunnel})

	x.emitStatus(EngineDisconnecting, "[Xray] Disconnecting")
	os.mu.Lock()
	os.tunnel = 0
	os.mu.Unlock()
	x.emitStatus(EngineDisconnected, "[Xray] Disconnected")
	events.wait(hotspotSharingEvent{Shared: hotspotSharedTunnel, Blocked: true})

	x.emitStatus(StatsEvent, "{}")
	if !events.expectNone(100 * time.Millisecond) {
		t.Error("a stats event moved the hotspot")
	}

	x.replayHotspot()
	events.wait(hotspotSharingEvent{Shared: hotspotSharedTunnel, Blocked: true})
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

// useFakeHotspotOS makes the controller's hotspot orders run over a fake, and
// closes the order a test left.
func useFakeHotspotOS(t *testing.T, x *CoreController) *fakeHotspotOS {
	t.Helper()
	os := newFakeHotspotOS()
	previous := hotspotOSFactory
	hotspotOSFactory = func() hotspotOS { return os }
	t.Cleanup(func() {
		hotspotOSFactory = previous
		if sharing := x.hotspot.Swap(nil); sharing != nil {
			sharing.close()
		}
	})
	return os
}

// setHotspotSharing builds the order from what the controller knows: the phase
// the engine's events last said.
func TestSetHotspotSharingStartsFromTheEnginePhase(t *testing.T) {
	x := &CoreController{}
	os := useFakeHotspotOS(t, x)
	events := captureHotspotEvents(t)
	os.tunnel = testTunnel
	os.present[testTunnel] = true

	x.emitStatus(EngineConnecting, "[Xray] Connecting")
	x.emitStatus(EngineConnected, "[Xray] Connected")
	if got := x.setHotspotSharing(hotspotSharingRequest{On: true, BlockWhileTunnelDown: true}); got != ResultSuccess {
		t.Fatalf("setHotspotSharing = %d", got)
	}
	// The tunnel is up when the hotspot is asked for: it shares the tunnel.
	events.wait(hotspotSharingEvent{Shared: hotspotSharedTunnel})
	if got := os.callsMatching("share 7 9"); got != 1 {
		t.Errorf("shared the tunnel %d times: %v", got, os.calls)
	}
}

// A session started in proxy mode has no tunnel: the order sees it through the
// controller's flag, which engineStart sets. Without it a session that says it
// is up and has no adapter is a tunnel that has not come, and forwards nothing.
func TestSetHotspotSharingKnowsAProxySession(t *testing.T) {
	for name, tc := range map[string]struct {
		opts map[string]string
		want hotspotSharingEvent
	}{
		"proxy mode": {opts: map[string]string{"proxyPort": "1080"}, want: hotspotSharingEvent{Shared: hotspotSharedWiFi}},
		"tunnel":     {opts: map[string]string{}, want: hotspotSharingEvent{Shared: hotspotSharedNone, Blocked: true}},
	} {
		t.Run(name, func(t *testing.T) {
			x := &CoreController{}
			useFakeHotspotOS(t, x)
			events := captureHotspotEvents(t)

			registerEngine(refusingEngine{})
			t.Cleanup(func() { delete(engineRegistry, refusingEngine{}.ID()) })
			x.engineStart(refusingEngine{}.ID(), EngineStartRequest{Opts: tc.opts})
			x.emitStatus(EngineConnected, "connected")

			if got := x.setHotspotSharing(hotspotSharingRequest{On: true}); got != ResultSuccess {
				t.Fatalf("setHotspotSharing = %d", got)
			}
			events.wait(tc.want)
		})
	}
}

// refusingEngine starts nothing: engineStart records the session's mode before
// it asks the engine.
type refusingEngine struct{}

func (refusingEngine) ID() string                                      { return "hotspot-refusing" }
func (refusingEngine) Start(*CoreController, EngineStartRequest) int32 { return glitchCoreResultError }
func (refusingEngine) Stop(*CoreController) int32                      { return glitchCoreResultError }
func (refusingEngine) IsRunning(*CoreController) int32                 { return glitchCoreResultError }
func (refusingEngine) Traffic(*CoreController) (uint64, uint64, bool)  { return 0, 0, false }

// An order created later reads the phase inside its own lock, so an event that
// arrives through setPhase meanwhile is not overwritten by an older reading.
func TestAdoptPhaseReadsTheEngineUnderTheOrdersLock(t *testing.T) {
	sharing := newHotspotSharing(newFakeHotspotOS(), func(string) {}, tunnelDown)
	sharing.adoptPhase(func() tunnelPhase {
		if sharing.mu.TryLock() {
			sharing.mu.Unlock()
			t.Error("the engine's phase was read outside the order's lock")
		}
		return tunnelUp
	})
	if sharing.phase != tunnelUp {
		t.Errorf("phase = %v, want up", sharing.phase)
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
	sharing := newHotspotSharing(os, func(string) {}, tunnelPhase(x.enginePhase.Load()))
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

// A hotspot that starts after the repair began is not restarted with ICS.
func TestRestartUnlessHotspotRunsLeavesAHotspotThatStarted(t *testing.T) {
	os := newFakeHotspotOS()
	os.hotspotUp = false
	restarted := 0
	restart := func() error { restarted++; return nil }

	if err := restartUnlessHotspotRuns(os, restart); err != nil || restarted != 1 {
		t.Fatalf("with no hotspot: err %v, restarted %d times", err, restarted)
	}
	os.hotspotUp = true
	if err := restartUnlessHotspotRuns(os, restart); err != errHotspotStarted || restarted != 1 {
		t.Errorf("with a hotspot up: err %v, restarted %d times", err, restarted)
	}
}

// A hotspot runs when its adapter is up. A list of adapters that cannot be read
// does not say that none does, and what ICS reports says nothing either way.
func TestHotspotRunningIsTheAdapterBeingUp(t *testing.T) {
	os := newFakeHotspotOS()
	if !hotspotRunning(os) {
		t.Error("a hotspot adapter that is up was not seen")
	}
	os.public, os.private = math.MaxUint32, math.MaxUint32
	if !hotspotRunning(os) {
		t.Error("an adapter that is up read as no hotspot because ICS reports no pair")
	}
	os.hotspotUp = false
	os.public, os.private = testWiFi, testHotspot
	os.forged = &[2]uint32{testWiFi, testLAN}
	if hotspotRunning(os) {
		t.Error("a pair that ICS reports read as a hotspot with its adapter down")
	}
	os.hotspotErr = errors.New("cannot list adapters")
	if !hotspotRunning(os) {
		t.Error("adapters that cannot be listed read as no hotspot")
	}
}
