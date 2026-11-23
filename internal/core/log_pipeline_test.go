package core

import (
	"encoding/json"
	"log"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/conninspect"
	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

type capturedLog struct {
	code      int32
	Level     string `json:"level"`
	Component string `json:"component"`
	Message   string `json:"message"`
}

func replaceController(t *testing.T, next *CoreController) {
	t.Helper()
	previous := globalController.Load()
	globalController.Store(next)
	t.Cleanup(func() { globalController.Store(previous) })
}

// collectEvents keeps one code and drops it; a log line needs both codes and
// which one it travelled as.
//
// captureLogs wires the standard log package the way Initialize does, points
// the status sink at a recorder, and sets the verbosity atomic directly:
// applyStatusVerbosity would take the service-IPC branch on Windows.
func captureLogs(t *testing.T, verbosity int32) func() []capturedLog {
	t.Helper()
	replaceController(t, &CoreController{})

	var mu sync.Mutex
	var got []capturedLog
	setStatusSink(func(code int32, message string) {
		if code != LogEvent && code != LogError {
			return
		}
		entry := capturedLog{code: code}
		if err := json.Unmarshal([]byte(message), &entry); err != nil {
			t.Errorf("log payload is not JSON: %q", message)
		}
		mu.Lock()
		got = append(got, entry)
		mu.Unlock()
	})
	t.Cleanup(func() { setStatusSink(nil) })

	prevV := atomic.LoadInt32(&statusVerbosity)
	atomic.StoreInt32(&statusVerbosity, verbosity)
	t.Cleanup(func() { atomic.StoreInt32(&statusVerbosity, prevV) })

	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(sinkWriter{})
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	return func() []capturedLog {
		mu.Lock()
		defer mu.Unlock()
		return append([]capturedLog(nil), got...)
	}
}

func assertLogs(t *testing.T, got, want []capturedLog) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestLogPipeline_LevelIsTheWritersNotTheWords(t *testing.T) {
	logs := captureLogs(t, 2)

	log.Printf("[Xray] Connecting")
	log.Printf("[AWG] some error occurred, handshake failed")
	logfmt.Errorf("[AWG] tunnel broke")
	logfmt.Warnf("[IPC] set verbosity failed: %v", "pipe closed")
	emitLog(logfmt.Info, "mihomo", "fatal-looking words in an info line")

	want := []capturedLog{
		{LogEvent, "info", "Xray", "Connecting"},
		{LogEvent, "info", "AWG", "some error occurred, handshake failed"},
		{LogError, "error", "AWG", "tunnel broke"},
		{LogEvent, "warn", "IPC", "set verbosity failed: pipe closed"},
		{LogEvent, "info", "mihomo", "fatal-looking words in an info line"},
	}
	assertLogs(t, logs(), want)
}

func TestLogPipeline_VerbosityGatesByLevel(t *testing.T) {
	logs := captureLogs(t, 0)

	log.Printf("[Xray] Connecting")
	log.Printf("[Xray] tun2socks start failed")
	logfmt.Warnf("[Xray] retrying")
	logfmt.Errorf("[Xray] Failed to start Xray: boom")
	emitLog(logfmt.Fatal, "tun2socks", "engine died")

	got := logs()
	if len(got) != 2 || got[0].Level != "error" || got[1].Level != "fatal" {
		t.Fatalf("verbosity 0 forwards error and fatal only, got %+v", got)
	}
	for _, l := range got {
		if l.code != LogError {
			t.Errorf("%+v travelled as %d, want LogError", l, l.code)
		}
	}
}

func TestLogPipeline_OffDropsEverything(t *testing.T) {
	logs := captureLogs(t, -1)

	logfmt.Errorf("[Xray] Failed to start Xray: boom")
	emitLog(logfmt.Fatal, "tun2socks", "engine died")

	if got := logs(); len(got) != 0 {
		t.Fatalf("verbosity -1 must drop every line, got %+v", got)
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
	if !logEnabled(logfmt.Debug) {
		t.Error("verbosity 2 should forward a debug line")
	}

	applyStatusVerbosity(0)
	if got := atomic.LoadInt32(&statusVerbosity); got != 0 {
		t.Fatalf("after applyStatusVerbosity(0): statusVerbosity=%d, want 0", got)
	}
	if logEnabled(logfmt.Debug) {
		t.Error("verbosity 0 should drop a debug line")
	}
	if !logEnabled(logfmt.Fatal) {
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
	if logEnabled(logfmt.Fatal) {
		t.Error("verbosity -1 (off) must drop even fatal lines")
	}
}

// A line the service sends is held to this process's verbosity, which may be
// lower than the one another client left the service at.
func TestRelayedLogPasses_HoldsServiceLinesToTheLocalGate(t *testing.T) {
	prevV := atomic.LoadInt32(&statusVerbosity)
	t.Cleanup(func() { atomic.StoreInt32(&statusVerbosity, prevV) })

	info := logfmt.BuildJSON(logfmt.Info, "Xray", "Connecting")
	failure := logfmt.BuildJSON(logfmt.Error, "Xray", "Failed to start")

	atomic.StoreInt32(&statusVerbosity, -1)
	if relayedLogPasses(LogError, failure) {
		t.Error("verbosity -1 let a relayed error line through")
	}
	if !relayedLogPasses(EngineConnected, "[Xray] Connected") {
		t.Error("the gate held back a lifecycle event")
	}

	atomic.StoreInt32(&statusVerbosity, 0)
	if relayedLogPasses(LogEvent, info) || !relayedLogPasses(LogError, failure) {
		t.Error("verbosity 0 must pass the error line and drop the info line")
	}
	if relayedLogPasses(LogEvent, "not json") {
		t.Error("a relayed log payload that does not parse must be dropped")
	}
}

func TestLogPipeline_ScrubsBeforeThePayload(t *testing.T) {
	const link = `vless://b831381d-6324-4d53-ad4f-8cda48b30811@203.0.113.9:443?pbk=Qzm3mXq2Gk5n0yR7vT1cF8hJ4pL6sW9aBxDeNuIoKtE`
	logs := captureLogs(t, 2)

	logfmt.Errorf(`[Xray] Failed to start Xray: parse "%s"`, link)
	assertLogs(t, logs(), []capturedLog{
		{LogError, "error", "Xray", `Failed to start Xray: parse "vless://[redacted]"`},
	})

	var lifecycle []string
	setStatusSink(func(code int32, message string) { lifecycle = append(lifecycle, message) })
	globalController.Load().emitStatus(EngineError, `[Xray] Failed to start: parse "`+link+`": invalid port`)
	if len(lifecycle) != 1 || lifecycle[0] != `[Xray] Failed to start: parse "vless://[redacted]": invalid port` {
		t.Fatalf("EngineError text = %q", lifecycle)
	}
}

func TestEmitStatus_DefersInOrderDuringFFICall(t *testing.T) {
	controller := &CoreController{}
	replaceController(t, controller)
	prevV := atomic.LoadInt32(&statusVerbosity)
	atomic.StoreInt32(&statusVerbosity, 2)
	t.Cleanup(func() { atomic.StoreInt32(&statusVerbosity, prevV) })
	prevInspector := connInspectEnabled.Load()
	connInspectEnabled.Store(true)
	t.Cleanup(func() { connInspectEnabled.Store(prevInspector) })

	var mu sync.Mutex
	var codes []int32
	done := make(chan struct{})
	setStatusSink(func(code int32, _ string) {
		mu.Lock()
		codes = append(codes, code)
		if code == EngineConnected {
			close(done)
		}
		mu.Unlock()
	})
	t.Cleanup(func() { setStatusSink(nil) })

	runFFICall(func() int32 {
		controller.emitStatus(EngineConnecting, "[Xray] Connecting")
		for i := 0; i < 50; i++ {
			emitLog(logfmt.Info, "Xray", "starting")
			controller.emitConn(conninspect.Record{Engine: "xray", Host: "example.com", Port: "443"})
		}
		return 0
	})
	controller.emitStatus(EngineConnected, "[Xray] Connected")

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the events never arrived")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(codes) != 102 || codes[0] != EngineConnecting || codes[101] != EngineConnected {
		t.Fatalf("got %d events, first %v, last %v", len(codes), codes[:1], codes[len(codes)-1:])
	}
	for i := 1; i <= 100; i++ {
		want := int32(LogEvent)
		if i%2 == 0 {
			want = ConnEvent
		}
		if codes[i] != want {
			t.Fatalf("event %d = %d, want %d", i, codes[i], want)
		}
	}
}

// stalledSink delivers nothing until release is closed, then records the codes
// in the order they arrive.
type stalledSink struct {
	release chan struct{}
	mu      sync.Mutex
	got     []int32
}

func newStalledSink() *stalledSink {
	return &stalledSink{release: make(chan struct{})}
}

func (s *stalledSink) deliver(code int32, _ string) {
	<-s.release
	s.mu.Lock()
	s.got = append(s.got, code)
	s.mu.Unlock()
}

// delivered releases the sink and returns what it got once last arrives.
func (s *stalledSink) delivered(t *testing.T, last int32) []int32 {
	t.Helper()
	close(s.release)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		got := slices.Clone(s.got)
		s.mu.Unlock()
		if len(got) > 0 && got[len(got)-1] == last {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("event %d never arrived", last)
	return nil
}

// Replacing the controller while an engine goroutine is in emitLog is what a
// test's cleanup does during another engine's line. The race detector is the
// assertion.
func TestEmitLog_ReplacingTheControllerDoesNotRace(t *testing.T) {
	previous := globalController.Load()
	t.Cleanup(func() { globalController.Store(previous) })
	verbosity := atomic.LoadInt32(&statusVerbosity)
	atomic.StoreInt32(&statusVerbosity, 2)
	t.Cleanup(func() { atomic.StoreInt32(&statusVerbosity, verbosity) })
	setStatusSink(func(int32, string) {})
	t.Cleanup(func() { setStatusSink(nil) })

	waitForMirrorIdle()
	discard, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	previousOut := os.Stdout
	os.Stdout = discard
	t.Cleanup(func() {
		waitForMirrorIdle()
		os.Stdout = previousOut
		_ = discard.Close()
	})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				emitLog(logfmt.Info, "core", "line")
			}
		}
	}()
	for range 1000 {
		globalController.Store(&CoreController{})
	}
	close(stop)
	wg.Wait()
}

// A sink that stalls behind a burst sheds the oldest log and connection
// events, never a lifecycle event.
func TestDeferredStatus_ShedsOnlyLogAndConnEventsWhenFull(t *testing.T) {
	var q statusQueue
	sink := newStalledSink()
	q.offer(statusEvent{sink.deliver, EngineConnecting, ""}, true)
	for i := 0; i < maxDeferredStatus+100; i++ {
		q.offer(statusEvent{sink.deliver, LogEvent, ""}, true)
	}
	q.offer(statusEvent{sink.deliver, EngineConnected, ""}, true)

	got := sink.delivered(t, EngineConnected)
	if got[0] != EngineConnecting {
		t.Fatalf("lifecycle events lost or reordered: first %d", got[0])
	}
	if len(got) > maxDeferredStatus+2 {
		t.Fatalf("%d events delivered, the queue holds %d", len(got), maxDeferredStatus)
	}
}

func TestDeferredStatus_DropsQueuedTrafficEventsButKeepsTheRest(t *testing.T) {
	var q statusQueue
	sink := newStalledSink()
	q.offer(statusEvent{sink.deliver, EngineConnecting, ""}, true)
	for _, code := range []int32{LogEvent, ConnEvent, LogError, EngineConnected} {
		q.offer(statusEvent{sink.deliver, code, ""}, true)
	}
	q.dropTrafficEvents()

	// The first event may already be on its way to the sink when the drop runs.
	want := []int32{EngineConnecting, EngineConnected}
	if got := sink.delivered(t, EngineConnected); !slices.Equal(got, want) {
		t.Fatalf("delivered %v, want %v", got, want)
	}
}
