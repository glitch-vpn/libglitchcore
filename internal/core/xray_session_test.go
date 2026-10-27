//go:build !no_xray

package core

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
)

// holdXrayStarts parks every start before it takes coreMutex until the test
// lets the start of that session generation go.
func holdXrayStarts(t *testing.T) (release func(mark int64)) {
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
	prev := xrayStartGate
	xrayStartGate = func(mark int64) { <-gate(mark) }
	t.Cleanup(func() { xrayStartGate = prev })
	return func(mark int64) { close(gate(mark)) }
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

// Connect, disconnect, connect, disconnect, each before the core gets to the
// last: the second disconnect lands after the first start gave up and while
// the second still waits, and must be taken.
func TestXrayStop_TakenWhileALaterStartWaits(t *testing.T) {
	logs := captureLogs(t, 1)
	release := holdXrayStarts(t)
	x := &CoreController{}
	x.initEngineState()
	req := EngineStartRequest{Config: "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:9?security=none&type=tcp#t"}

	if res := x.HandleXrayStart(req); res != glitchCoreResultSuccess {
		t.Fatalf("first start = %d", res)
	}
	if res := x.HandleXrayStop(); res != glitchCoreResultSuccess {
		t.Fatalf("stop during the first start = %d", res)
	}
	if res := x.HandleXrayStart(req); res != glitchCoreResultSuccess {
		t.Fatalf("second start = %d", res)
	}
	release(0)
	waitStartsGivenUp(t, logs, 1)

	if res := x.HandleXrayStop(); res != glitchCoreResultSuccess {
		t.Fatalf("stop while the second start waits = %d, want it taken", res)
	}
	release(1)
	waitStartsGivenUp(t, logs, 2)

	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()
	if x.isXrayRunning.Load() || x.xrayCoreInstance != nil {
		t.Fatal("xray runs after both starts were stopped")
	}
}

// A stop queued behind a later start that got the lock first must not close
// the instance that start brought up: its loops keep reading it.
func TestXrayStop_LeavesTheInstanceOfALaterStart(t *testing.T) {
	x := &CoreController{}
	x.isXrayRunning.Store(true)
	x.xrayInstanceGen.Store(2)

	if err := x.xrayStop(2); !errors.Is(err, errStopSuperseded) {
		t.Fatalf("stop of generation 2 over an instance started under 2: %v", err)
	}
	if !x.isXrayRunning.Load() {
		t.Fatal("the stop marked the later session's engine stopped")
	}
}

func holdXrayStops(t *testing.T) (release func()) {
	t.Helper()
	gate := make(chan struct{})
	prev := xrayStopGate
	xrayStopGate = func(int64) { <-gate }
	t.Cleanup(func() { xrayStopGate = prev })
	return func() { close(gate) }
}

func proxyModeStart(t *testing.T) (EngineStartRequest, string) {
	t.Helper()
	t.Setenv("GLITCH_SOCKS_READY_TIMEOUT_SEC", "20")
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	return EngineStartRequest{
		Config: "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:9?security=none&type=tcp#t",
		Opts: map[string]string{
			"proxyPort":         strconv.Itoa(port),
			"resolveExternalIp": "0",
			"livenessSec":       "300",
		},
	}, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

func listens(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// Connect A comes up, disconnect S is queued behind connect B, and B takes
// the lock first: B replaces A's instance instead of reporting connected on
// it, and S then leaves B's alone.
func TestXrayStart_ReplacesTheInstanceOfAStoppedSession(t *testing.T) {
	var mu sync.Mutex
	var lifecycle []int32
	setStatusSink(func(code int32, _ string) {
		if code >= EngineConnecting && code <= EngineStopRejectedNotRunning {
			mu.Lock()
			lifecycle = append(lifecycle, code)
			mu.Unlock()
		}
	})
	t.Cleanup(func() { setStatusSink(nil) })
	connected := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, c := range lifecycle {
			if c == EngineConnected {
				n++
			}
		}
		return n
	}
	waitConnected := func(want int) {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); connected() < want; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("connected %d times, want %d", connected(), want)
			}
		}
	}

	releaseStart := holdXrayStarts(t)
	releaseStop := holdXrayStops(t)
	x := &CoreController{}
	x.initEngineState()
	t.Cleanup(func() {
		x.coreMutex.Lock()
		defer x.coreMutex.Unlock()
		x.xrayStopLocked()
	})
	startA, addrA := proxyModeStart(t)
	startB, addrB := proxyModeStart(t)

	if res := x.HandleXrayStart(startA); res != glitchCoreResultSuccess {
		t.Fatalf("start A = %d", res)
	}
	releaseStart(0)
	waitConnected(1)

	if res := x.HandleXrayStop(); res != glitchCoreResultSuccess {
		t.Fatalf("stop S = %d", res)
	}
	if res := x.HandleXrayStart(startB); res != glitchCoreResultSuccess {
		t.Fatalf("start B = %d", res)
	}
	releaseStart(1)
	waitConnected(2)
	releaseStop()
	time.Sleep(200 * time.Millisecond)

	x.coreMutex.Lock()
	running, gen := x.isXrayRunning.Load(), x.xrayInstanceGen.Load()
	x.coreMutex.Unlock()
	if !running || gen != 1 {
		t.Fatalf("running %v under generation %d, want B's instance (generation 1)", running, gen)
	}
	if !listens(addrB) {
		t.Fatal("B's proxy is not up")
	}
	if listens(addrA) {
		t.Fatal("A's proxy still answers")
	}
	mu.Lock()
	last := lifecycle[len(lifecycle)-1]
	mu.Unlock()
	if connected() != 2 || last != EngineConnected {
		t.Fatalf("lifecycle %v: want A's and B's connected, B's last", lifecycle)
	}
}
