package core

import (
	"context"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/serverinfo"
)

// gateHook is the test's side of engineStartGate and engineStopGate. A stop
// or start a test left behind still reads the gate after the test is over, so
// the package variable is written once, before any test runs, and a test swaps
// only the hook under the lock.
type gateHook struct {
	mu sync.RWMutex
	fn func(engine string, generation int64)
}

func (h *gateHook) set(fn func(engine string, generation int64)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fn = fn
}

func (h *gateHook) call(engine string, generation int64) {
	h.mu.RLock()
	fn := h.fn
	h.mu.RUnlock()
	if fn != nil {
		fn(engine, generation)
	}
}

var startGates, stopGates gateHook

func init() {
	engineStartGate = startGates.call
	engineStopGate = stopGates.call
}

// holdStarts parks every start of engine before it takes coreMutex until the
// test lets the start of that session generation go.
func holdStarts(t *testing.T, engine string) (release func(mark int64)) {
	t.Helper()
	var mu sync.Mutex
	gates := map[int64]chan struct{}{}
	gate := func(mark int64) chan struct{} {
		mu.Lock()
		defer mu.Unlock()
		if gates[mark] == nil {
			gates[mark] = make(chan struct{})
		}
		return gates[mark]
	}
	startGates.set(func(e string, mark int64) {
		if e == engine {
			<-gate(mark)
		}
	})
	t.Cleanup(func() { startGates.set(nil) })
	return func(mark int64) { close(gate(mark)) }
}

func holdStops(t *testing.T, engine string) (release func()) {
	t.Helper()
	gate := make(chan struct{})
	stopGates.set(func(e string, _ int64) {
		if e == engine {
			<-gate
		}
	})
	t.Cleanup(func() { stopGates.set(nil) })
	return func() { close(gate) }
}

type lifecycleLog struct {
	mu    sync.Mutex
	codes []int32
	// Called after each lifecycle event is recorded, outside the lock; set
	// before the first event.
	onEvent func(code int32)
}

func recordLifecycle(t *testing.T) *lifecycleLog {
	t.Helper()
	l := &lifecycleLog{}
	setStatusSink(func(code int32, _ string) {
		if code >= EngineConnecting && code <= EngineStopRejectedNotRunning {
			l.mu.Lock()
			l.codes = append(l.codes, code)
			l.mu.Unlock()
			if l.onEvent != nil {
				l.onEvent(code)
			}
		}
	})
	t.Cleanup(func() { setStatusSink(nil) })
	return l
}

func (l *lifecycleLog) snapshot() []int32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]int32(nil), l.codes...)
}

func (l *lifecycleLog) count(code int32) int {
	n := 0
	for _, c := range l.snapshot() {
		if c == code {
			n++
		}
	}
	return n
}

func (l *lifecycleLog) waitFor(t *testing.T, code int32, n int) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); l.count(code) < n; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("lifecycle %v: want %d of %d", l.snapshot(), n, code)
		}
	}
}

// waitStartsGivenUp waits until want starts have returned for a stop that came
// before them.
func waitStartsGivenUp(t *testing.T, logs func() []capturedLog, want int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		givenUp := 0
		for _, l := range logs() {
			if strings.Contains(l.Message, "stopped before startup") {
				givenUp++
			}
		}
		if givenUp == want {
			return
		}
	}
	t.Fatalf("fewer than %d starts gave up", want)
}

// queuedStopScenario: connect, disconnect, connect, disconnect, each before
// the core gets to the last. The second disconnect lands after the first
// start gave up and while the second still waits, and must be taken; at the
// end nothing runs.
func queuedStopScenario(t *testing.T, x *CoreController, engine string, s *engineSession, start func(EngineStartRequest) int32, stop func() int32, req EngineStartRequest) {
	t.Helper()
	logs := captureLogs(t, 1)
	release := holdStarts(t, engine)

	if res := start(req); res != glitchCoreResultSuccess {
		t.Fatalf("first start = %d", res)
	}
	if res := stop(); res != glitchCoreResultSuccess {
		t.Fatalf("stop during the first start = %d", res)
	}
	if res := start(req); res != glitchCoreResultSuccess {
		t.Fatalf("second start = %d", res)
	}
	release(0)
	waitStartsGivenUp(t, logs, 1)

	if res := stop(); res != glitchCoreResultSuccess {
		t.Fatalf("stop while the second start waits = %d, want it taken", res)
	}
	release(1)
	waitStartsGivenUp(t, logs, 2)
	waitStartsInFlight(t, s, 0)

	if s.running.Load() {
		t.Fatal("the engine runs after both starts were stopped")
	}
}

// stopDuringStartScenario: a disconnect lands while the start still waits for
// the core, takes it first and closes nothing; the start then gives up.
// Disconnected waits for that start to return, as the engine counts as running
// until then.
func stopDuringStartScenario(t *testing.T, s *engineSession, engine string, start func(EngineStartRequest) int32, stop, isRunning func() int32, req EngineStartRequest) {
	t.Helper()
	disconnected := make(chan struct{})
	var once sync.Once
	var runningAtDisconnect atomic.Int32
	setStatusSink(func(code int32, _ string) {
		if code == EngineDisconnected {
			runningAtDisconnect.Store(isRunning())
			once.Do(func() { close(disconnected) })
		}
	})
	t.Cleanup(func() { setStatusSink(nil) })
	release := holdStarts(t, engine)

	if res := start(req); res != glitchCoreResultSuccess {
		t.Fatalf("start = %d", res)
	}
	if res := stop(); res != glitchCoreResultSuccess {
		t.Fatalf("stop during the start = %d", res)
	}
	select {
	case <-disconnected:
		t.Fatalf("disconnected reported while the start it ended is in flight (running = %v)", isRunning() == glitchCoreResultSuccess)
	case <-time.After(300 * time.Millisecond):
	}

	release(0)
	select {
	case <-disconnected:
	case <-time.After(10 * time.Second):
		t.Fatal("no disconnected after the start returned")
	}
	if runningAtDisconnect.Load() == glitchCoreResultSuccess {
		t.Fatal("the engine reads as running when disconnected is reported")
	}
	waitStartsInFlight(t, s, 0)
}

// replaceScenario: connect A comes up, disconnect S is queued behind connect
// B, and B takes the lock first. B replaces A's instance instead of reporting
// connected on it, and S then leaves B's alone: B's runs, connected twice (A,
// then B, last), no disconnect after.
func replaceScenario(t *testing.T, engine string, s *engineSession, start func(EngineStartRequest) int32, stop func() int32, reqA, reqB EngineStartRequest) {
	t.Helper()
	life := recordLifecycle(t)
	releaseStart := holdStarts(t, engine)
	releaseStop := holdStops(t, engine)

	if res := start(reqA); res != glitchCoreResultSuccess {
		t.Fatalf("start A = %d", res)
	}
	releaseStart(0)
	life.waitFor(t, EngineConnected, 1)

	if res := stop(); res != glitchCoreResultSuccess {
		t.Fatalf("stop S = %d", res)
	}
	if res := start(reqB); res != glitchCoreResultSuccess {
		t.Fatalf("start B = %d", res)
	}
	releaseStart(1)
	life.waitFor(t, EngineConnected, 2)
	waitStartsInFlight(t, s, 0)
	releaseStop()
	time.Sleep(200 * time.Millisecond)

	if !s.runsSession(1) {
		t.Fatalf("running %v under generation %d, want B's instance (generation 1)", s.running.Load(), s.instanceGen.Load())
	}
	codes := life.snapshot()
	if life.count(EngineConnected) != 2 || codes[len(codes)-1] != EngineConnected {
		t.Fatalf("lifecycle %v: want A's and B's connected, B's last", codes)
	}
	if life.count(EngineDisconnected) != 0 {
		t.Fatalf("lifecycle %v: a disconnect reported over B's session", codes)
	}
}

func loopbackProxyPort(t *testing.T) (port, addr string) {
	t.Helper()
	p, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	port = strconv.Itoa(p)
	return port, net.JoinHostPort("127.0.0.1", port)
}

func listens(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// The loops a stale start armed: a stop's own cleanup can run before the
// start arms them, and its stop can close the instance before the start's
// tail looks. Only a later start that replaced the instance owns them.
func TestAbortStaleEngineSession_EndsTheLoopsUnlessALaterStartOwnsThem(t *testing.T) {
	sessions := map[string]func(x *CoreController) *engineSession{
		"xray":   func(x *CoreController) *engineSession { return &x.xraySession },
		"mihomo": func(x *CoreController) *engineSession { return &x.mihomoSession },
	}
	cases := []struct {
		name      string
		instance  func(s *engineSession) // the engine's state when the start's tail looks
		loopsLeft bool
	}{
		{"its stop already closed the instance", func(s *engineSession) {}, false},
		{"its own instance still runs", func(s *engineSession) { s.up(0) }, false},
		{"a later start replaced it", func(s *engineSession) { s.up(1) }, true},
	}
	for engine, session := range sessions {
		for _, c := range cases {
			t.Run(engine+"/"+c.name, func(t *testing.T) {
				x := &CoreController{}
				x.startLiveness(livenessParams{engine: engine, interval: time.Hour, probe: func(context.Context) (time.Duration, error) { return 0, nil }})
				x.startSelectionWatch(serverinfo.Selection{}, func() int { return -1 })
				t.Cleanup(x.endSessionLoops)
				x.sessionGen.Store(1)
				c.instance(session(x))

				if !x.abortStaleEngineSession(session(x), 0) {
					t.Fatal("a start whose session moved on was not stale")
				}
				x.loopsMu.Lock()
				left := x.livenessQuit != nil || x.selWatchQuit != nil
				x.loopsMu.Unlock()
				if left != c.loopsLeft {
					t.Fatalf("loops left running = %v, want %v", left, c.loopsLeft)
				}
			})
		}
	}
}

// tunCopies stands in for the dup of a start's TUN copy: copy n of fd f is
// f+1000*n, and every close is recorded.
type tunCopies struct {
	mu     sync.Mutex
	dups   map[int]int
	closed []int
}

func standInTunCopies(t *testing.T) *tunCopies {
	t.Helper()
	c := &tunCopies{dups: map[int]int{}}
	prevDup, prevClose := dupRequestTun, closeRequestTun
	dupRequestTun = func(fd int) (int, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.dups[fd]++
		return fd + 1000*c.dups[fd], nil
	}
	closeRequestTun = func(fd int) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.closed = append(c.closed, fd)
	}
	t.Cleanup(func() { dupRequestTun, closeRequestTun = prevDup, prevClose })
	return c
}

func (c *tunCopies) snapshot() (dups map[int]int, closed []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dups = map[int]int{}
	for k, v := range c.dups {
		dups[k] = v
	}
	return dups, append([]int(nil), c.closed...)
}

func waitStartsInFlight(t *testing.T, s *engineSession, want int) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); s.startsInFlightCount() != want; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("starts in flight = %d, want %d", s.startsInFlightCount(), want)
		}
	}
}

// logLines collects the standard logger's lines for the test.
type logLines struct {
	mu    sync.Mutex
	lines []string
}

func (l *logLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, string(p))
	return len(p), nil
}

func (l *logLines) has(substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

func captureLogLines(t *testing.T) *logLines {
	t.Helper()
	l := &logLines{}
	prevOut := log.Writer()
	log.SetOutput(l)
	t.Cleanup(func() { log.SetOutput(prevOut) })
	return l
}

// waitStopWaiting waits until a stop that took the core has reached its wait
// for the starts it ended.
func waitStopWaiting(t *testing.T, s *engineSession) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		s.startsMu.Lock()
		waiting := s.startReturned != nil
		s.startsMu.Unlock()
		if waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the stop never reached its wait for the starts it ended")
		}
	}
}

const stopYieldedLog = "not reporting disconnected"

// waitStopYielded waits until the stop either reported Disconnected or left
// it to a later start, and says which.
func waitStopYielded(t *testing.T, logs *logLines, life *lifecycleLog) (reported bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if logs.has(stopYieldedLog) {
			return false
		}
		if life.count(EngineDisconnected) > 0 {
			return true
		}
	}
	t.Fatal("the stop neither reported Disconnected nor left it to a later start")
	return false
}

// laterStartScenario: connect A waits for the core, disconnect S takes it and
// waits for A, and connect B, requested after S on the same or the other
// engine, comes up first. Disconnected is then B's to be spared: it would
// land after B's Connected and read as B's session ending.
func laterStartScenario(t *testing.T, stopped *engineSession, engine string, startA func(EngineStartRequest) int32, stop func() int32, startB func(EngineStartRequest) int32, bRuns func() bool, reqA, reqB EngineStartRequest) {
	t.Helper()
	life := recordLifecycle(t)
	logs := captureLogLines(t)
	release := holdStarts(t, engine)

	if res := startA(reqA); res != glitchCoreResultSuccess {
		t.Fatalf("start A = %d", res)
	}
	if res := stop(); res != glitchCoreResultSuccess {
		t.Fatalf("stop S = %d", res)
	}
	waitStopWaiting(t, stopped)
	if res := startB(reqB); res != glitchCoreResultSuccess {
		t.Fatalf("start B = %d", res)
	}
	release(1)
	life.waitFor(t, EngineConnected, 1)
	release(0)
	if waitStopYielded(t, logs, life) {
		t.Fatalf("lifecycle %v: Disconnected after B's Connected while B runs = %v", life.snapshot(), bRuns())
	}
	waitStartsInFlight(t, stopped, 0)
	if !bRuns() {
		t.Fatal("B's engine does not run")
	}
}

// stopNotWaitingForLaterStartScenario: the stop waits for the starts it ended
// and for no other. B, requested after it, stays parked at its gate while the
// stop settles.
func stopNotWaitingForLaterStartScenario(t *testing.T, s *engineSession, engine string, start func(EngineStartRequest) int32, stop func() int32, reqA, reqB EngineStartRequest) {
	t.Helper()
	life := recordLifecycle(t)
	logs := captureLogLines(t)
	release := holdStarts(t, engine)

	if res := start(reqA); res != glitchCoreResultSuccess {
		t.Fatalf("start A = %d", res)
	}
	if res := stop(); res != glitchCoreResultSuccess {
		t.Fatalf("stop S = %d", res)
	}
	waitStopWaiting(t, s)
	if res := start(reqB); res != glitchCoreResultSuccess {
		t.Fatalf("start B = %d", res)
	}
	release(0)
	if waitStopYielded(t, logs, life) {
		t.Fatalf("lifecycle %v: Disconnected while B, begun after the stop, is in flight", life.snapshot())
	}
	release(1)
	waitStartsInFlight(t, s, 0)
}

// connectingAnnouncedAfterTheStartIsCountedScenario: connect A waits for the
// core, disconnect S waits for A, and connect B announces Connecting while A
// returns. The stop settles in that moment, and it has to find B counted:
// otherwise it reports Disconnected, then B reports Connected.
func connectingAnnouncedAfterTheStartIsCountedScenario(t *testing.T, s *engineSession, engine string, start func(EngineStartRequest) int32, stop func() int32, reqA, reqB EngineStartRequest) {
	t.Helper()
	life := recordLifecycle(t)
	logs := captureLogLines(t)
	release := holdStarts(t, engine)

	if res := start(reqA); res != glitchCoreResultSuccess {
		t.Fatalf("start A = %d", res)
	}
	if res := stop(); res != glitchCoreResultSuccess {
		t.Fatalf("stop S = %d", res)
	}
	waitStopWaiting(t, s)

	life.onEvent = func(code int32) {
		if code == EngineConnecting {
			release(0)
			waitStopYielded(t, logs, life)
		}
	}
	if res := start(reqB); res != glitchCoreResultSuccess {
		t.Fatalf("start B = %d", res)
	}
	release(1)
	life.waitFor(t, EngineConnected, 1)
	waitStartsInFlight(t, s, 0)
	if life.count(EngineDisconnected) != 0 {
		t.Fatalf("lifecycle %v: Disconnected over B's session", life.snapshot())
	}
}
