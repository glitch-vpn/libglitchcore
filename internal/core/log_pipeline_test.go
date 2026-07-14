package core

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

func TestStartupLogPipeline(t *testing.T) {
	prevCtl := globalController
	globalController = &CoreController{}
	globalController.initEngineState()
	t.Cleanup(func() { globalController = prevCtl })

	var mu sync.Mutex
	type ev struct {
		code int32
		msg  string
	}
	var got []ev
	setStatusSink(func(code int32, message string) {
		mu.Lock()
		got = append(got, ev{code, message})
		mu.Unlock()
	})
	t.Cleanup(func() { setStatusSink(nil) })

	logSink = routeLogToFFI
	t.Cleanup(func() { logSink = nil })

	// Verbosity 2 = forward everything. Set the atomic directly to avoid the
	// service-IPC branch in applyStatusVerbosity on Windows.
	prevV := atomic.LoadInt32(&statusVerbosity)
	atomic.StoreInt32(&statusVerbosity, 2)
	t.Cleanup(func() { atomic.StoreInt32(&statusVerbosity, prevV) })

	// Drive the writer that log.SetOutput(sinkWriter{}) installs.
	sw := sinkWriter{}
	_, _ = sw.Write([]byte("[Xray] Connecting\n"))
	_, _ = sw.Write([]byte("[AWG] some error occurred\n"))
	// The explicit log-event emit used in awgStart/awgStop.
	globalController.emitStatus(LogEvent, logfmt.BuildJSON("info", "AWG", "AWG started"))

	mu.Lock()
	defer mu.Unlock()

	if len(got) != 3 {
		t.Fatalf("expected 3 delivered events, got %d: %#v", len(got), got)
	}
	for i, e := range got {
		if !strings.HasPrefix(e.msg, "{") || !strings.Contains(e.msg, `"message":`) {
			t.Fatalf("event %d is not a JSON log line: %q", i, e.msg)
		}
	}
	if got[0].code != LogEvent {
		t.Errorf("info line -> code %d, want LogEvent (%d)", got[0].code, LogEvent)
	}
	if got[1].code != LogError {
		t.Errorf("error line -> code %d, want LogError (%d)", got[1].code, LogError)
	}
	if !strings.Contains(got[1].msg, `"level":"error"`) || !strings.Contains(got[1].msg, `"component":"AWG"`) {
		t.Errorf("error line JSON malformed: %q", got[1].msg)
	}
	if got[2].code != LogEvent {
		t.Errorf("explicit emit -> code %d, want LogEvent (%d)", got[2].code, LogEvent)
	}
}

func TestStartupLogPipeline_VerbosityFilter(t *testing.T) {
	prevCtl := globalController
	globalController = &CoreController{}
	globalController.initEngineState()
	t.Cleanup(func() { globalController = prevCtl })

	var mu sync.Mutex
	var got int
	setStatusSink(func(code int32, message string) {
		mu.Lock()
		got++
		mu.Unlock()
	})
	t.Cleanup(func() { setStatusSink(nil) })

	logSink = routeLogToFFI
	t.Cleanup(func() { logSink = nil })

	prevV := atomic.LoadInt32(&statusVerbosity)
	atomic.StoreInt32(&statusVerbosity, 0) // errors only
	t.Cleanup(func() { atomic.StoreInt32(&statusVerbosity, prevV) })

	sw := sinkWriter{}
	_, _ = sw.Write([]byte("[Xray] Connecting\n"))             // info -> dropped
	_, _ = sw.Write([]byte("[Xray] Starting core\n"))          // info -> dropped
	_, _ = sw.Write([]byte("[Xray] tun2socks start failed\n")) // error -> forwarded

	mu.Lock()
	defer mu.Unlock()
	if got != 1 {
		t.Fatalf("at verbosity 0 expected only the error line forwarded, got %d events", got)
	}
}

// -1 = logging fully off (the default). Verbosity is re-read per log line, so a runtime
// change flips the outcome for the same line; out-of-range clamps to [-1,2].
func TestApplyStatusVerbosity_RuntimeChange(t *testing.T) {
	prev := atomic.LoadInt32(&statusVerbosity)
	t.Cleanup(func() { atomic.StoreInt32(&statusVerbosity, prev) })

	applyStatusVerbosity(2)
	if got := atomic.LoadInt32(&statusVerbosity); got != 2 {
		t.Fatalf("after applyStatusVerbosity(2): statusVerbosity=%d, want 2", got)
	}
	if !shouldEmitStatusMessage("[Xray] some debug detail") {
		t.Error("verbosity 2 should forward a debug line")
	}

	applyStatusVerbosity(0)
	if got := atomic.LoadInt32(&statusVerbosity); got != 0 {
		t.Fatalf("after applyStatusVerbosity(0): statusVerbosity=%d, want 0", got)
	}
	if shouldEmitStatusMessage("[Xray] some debug detail") {
		t.Error("verbosity 0 should drop a debug line")
	}
	if !shouldEmitStatusMessage("[Xray] fatal: boom") {
		t.Error("verbosity 0 must still forward fatal")
	}

	applyStatusVerbosity(99)
	if got := atomic.LoadInt32(&statusVerbosity); got != 2 {
		t.Errorf("applyStatusVerbosity(99) clamped to %d, want 2", got)
	}
	applyStatusVerbosity(-5)
	if got := atomic.LoadInt32(&statusVerbosity); got != -1 {
		t.Errorf("applyStatusVerbosity(-5) clamped to %d, want -1", got)
	}
	if shouldEmitStatusMessage("[Xray] fatal: boom") {
		t.Error("verbosity -1 (off) must drop even fatal lines")
	}
}
