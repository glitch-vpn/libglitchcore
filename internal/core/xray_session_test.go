//go:build !no_xray

package core

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
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
	x.xrayInstanceGen = 2

	if err := x.xrayStop(2); !errors.Is(err, errStopSuperseded) {
		t.Fatalf("stop of generation 2 over an instance started under 2: %v", err)
	}
	if !x.isXrayRunning.Load() {
		t.Fatal("the stop marked the later session's engine stopped")
	}
}
