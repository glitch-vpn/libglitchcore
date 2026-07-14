//go:build linux

package core

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestController() *CoreController {
	return &CoreController{
		nextHandle: 1,
	}
}

// Window between an old Dart isolate dying and a new one registering.
func TestEmitStatus_NilSink(t *testing.T) {
	ctl := newTestController()
	setStatusSink(nil)

	ctl.emitStatus(EngineConnected, "test")
}

func TestEmitStatus_ReceivesCallback(t *testing.T) {
	ctl := newTestController()

	var gotCode int32
	var gotMsg string
	var mu sync.Mutex

	setStatusSink(func(code int32, message string) {
		mu.Lock()
		gotCode = code
		gotMsg = message
		mu.Unlock()
	})
	defer setStatusSink(nil)

	ctl.emitStatus(EngineConnected, "hello")

	mu.Lock()
	defer mu.Unlock()
	if gotCode != EngineConnected {
		t.Errorf("code = %d, want %d", gotCode, EngineConnected)
	}
	if gotMsg != "hello" {
		t.Errorf("msg = %q, want %q", gotMsg, "hello")
	}
}

func TestEmitStatus_DisableReEnable(t *testing.T) {
	ctl := newTestController()

	var callCount atomic.Int32

	sink1 := func(code int32, message string) {
		callCount.Add(1)
	}
	setStatusSink(sink1)

	ctl.emitStatus(StatsEvent, "first")
	if c := callCount.Load(); c != 1 {
		t.Fatalf("after first emit: count = %d, want 1", c)
	}

	// InitDartApiDL disables the old callback.
	setStatusSink(nil)

	ctl.emitStatus(StatsEvent, "should be dropped")
	if c := callCount.Load(); c != 1 {
		t.Fatalf("after disabled emit: count = %d, want 1 (unchanged)", c)
	}

	// Re-register (new isolate).
	var reCount atomic.Int32
	sink2 := func(code int32, message string) {
		reCount.Add(1)
	}
	setStatusSink(sink2)
	defer setStatusSink(nil)

	ctl.emitStatus(StatsEvent, "second")
	if c := reCount.Load(); c != 1 {
		t.Fatalf("after re-enable emit: count = %d, want 1", c)
	}
	if c := callCount.Load(); c != 1 {
		t.Fatalf("old sink count = %d, want 1 (unchanged)", c)
	}
}

// Keeps the stats test independent of which engines this composition links.
type fakeTrafficEngine struct{}

func (fakeTrafficEngine) ID() string { return "fake" }
func (fakeTrafficEngine) Start(*CoreController, EngineStartRequest) int32 {
	return glitchCoreResultError
}
func (fakeTrafficEngine) Stop(*CoreController) int32                     { return glitchCoreResultError }
func (fakeTrafficEngine) IsRunning(*CoreController) int32                { return glitchCoreResultError }
func (fakeTrafficEngine) Traffic(*CoreController) (uint64, uint64, bool) { return 1, 1, true }

// InitDartApiDL calls stopStats to kill the goroutine before the old callback
// trampoline is freed.
func TestStopStats_StopsGoroutine(t *testing.T) {
	ctl := newTestController()

	var callCount atomic.Int32

	setStatusSink(func(code int32, message string) {
		callCount.Add(1)
	})
	defer setStatusSink(nil)

	registerEngine(fakeTrafficEngine{})
	defer delete(engineRegistry, "fake")
	ctl.connectedAtUnixMs.Store(time.Now().UnixMilli())

	ctl.startStats(20 * time.Millisecond)

	time.Sleep(100 * time.Millisecond)
	countBefore := callCount.Load()
	if countBefore == 0 {
		t.Fatal("stats goroutine did not emit any events")
	}

	ctl.stopStats()
	countStopped := callCount.Load()

	time.Sleep(100 * time.Millisecond)
	countAfter := callCount.Load()
	if countAfter != countStopped {
		t.Errorf("after stopStats returned: count went from %d to %d, want unchanged", countStopped, countAfter)
	}
}

// Deferring during inFFICall prevents re-entry from leaf FFI calls.
func TestEmitStatus_DeferredDuringFFICall(t *testing.T) {
	ctl := newTestController()

	var callCount atomic.Int32
	done := make(chan struct{}, 1)
	// Held across emitStatus: a synchronous callback would self-deadlock here,
	// and the deferred goroutine parks until the test has checked the count.
	var gate sync.Mutex
	gate.Lock()

	setStatusSink(func(code int32, message string) {
		gate.Lock()
		defer gate.Unlock()
		callCount.Add(1)
		done <- struct{}{}
	})
	defer setStatusSink(nil)

	inFFICall.Store(true)
	defer inFFICall.Store(false)

	ctl.emitStatus(EngineConnected, "deferred")

	if c := callCount.Load(); c != 0 {
		t.Fatalf("callback fired synchronously during inFFICall, count = %d", c)
	}
	gate.Unlock()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deferred callback did not fire")
	}

	if c := callCount.Load(); c != 1 {
		t.Errorf("deferred callback count = %d, want 1", c)
	}
}

func TestLogSink_NilWhenDisabled(t *testing.T) {
	ctl := newTestController()

	// Logs are OFF by default (statusVerbosity -1), so shouldEmitStatusMessage
	// drops everything. Raise to "all" to exercise the delivery path. Set the
	// atomic directly to avoid applyStatusVerbosity's Windows service-IPC branch.
	prevV := atomic.LoadInt32(&statusVerbosity)
	atomic.StoreInt32(&statusVerbosity, 2)
	t.Cleanup(func() { atomic.StoreInt32(&statusVerbosity, prevV) })

	var callCount atomic.Int32
	setStatusSink(func(code int32, message string) {
		callCount.Add(1)
	})

	// Set up logSink the same way InitializeController does.
	logSink = func(msg string) {
		if !shouldEmitStatusMessage(msg) {
			return
		}
		ctl.emitStatus(LogEvent, msg)
	}
	defer func() { logSink = nil }()

	logSink("test log message with error")
	if c := callCount.Load(); c != 1 {
		t.Fatalf("logSink delivered: count = %d, want 1", c)
	}

	// Disable sink (simulates hot restart).
	setStatusSink(nil)

	logSink("should be dropped error")
	if c := callCount.Load(); c != 1 {
		t.Fatalf("logSink after disable: count = %d, want 1 (unchanged)", c)
	}
}
