//go:build !no_xray

package core

import (
	"errors"
	"testing"
)

const xraySessionTestLink = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:9?security=none&type=tcp#t"

func xrayProxyStart(t *testing.T) (EngineStartRequest, string) {
	t.Helper()
	t.Setenv("GLITCH_SOCKS_READY_TIMEOUT_SEC", "20")
	port, addr := loopbackProxyPort(t)
	return EngineStartRequest{
		Config: xraySessionTestLink,
		Opts:   map[string]string{"proxyPort": port, "resolveExternalIp": "0", "livenessSec": "300"},
	}, addr
}

func TestXrayStop_TakenWhileALaterStartWaits(t *testing.T) {
	x := &CoreController{}
	x.initEngineState()
	queuedStopScenario(t, x, "xray", &x.xraySession, x.HandleXrayStart, x.HandleXrayStop,
		EngineStartRequest{Config: xraySessionTestLink})
}

func TestXrayStart_ReplacesTheInstanceOfAStoppedSession(t *testing.T) {
	x := &CoreController{}
	x.initEngineState()
	t.Cleanup(func() {
		x.stopStats()
		x.coreMutex.Lock()
		defer x.coreMutex.Unlock()
		x.endSessionLoops()
		x.xrayStopLocked()
	})
	reqA, addrA := xrayProxyStart(t)
	reqB, addrB := xrayProxyStart(t)

	replaceScenario(t, "xray", &x.xraySession, x.HandleXrayStart, x.HandleXrayStop, reqA, reqB)

	if !listens(addrB) {
		t.Fatal("B's proxy is not up")
	}
	if listens(addrA) {
		t.Fatal("A's proxy still answers")
	}
}

// A stop queued behind a later start that got the lock first must not close
// the instance that start brought up: its loops keep reading it.
func TestXrayStop_LeavesTheInstanceOfALaterStart(t *testing.T) {
	x := &CoreController{}
	x.xraySession.up(2)

	if err := x.xrayStop(2); !errors.Is(err, errStopSuperseded) {
		t.Fatalf("stop of generation 2 over an instance started under 2: %v", err)
	}
	if !x.xraySession.running.Load() {
		t.Fatal("the stop marked the later session's engine stopped")
	}
}
