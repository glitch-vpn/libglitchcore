//go:build !no_mihomo

package core

import (
	"errors"
	"os"
	"testing"
)

func mihomoProxyStart(t *testing.T, home string) (EngineStartRequest, string) {
	t.Helper()
	port, addr := loopbackProxyPort(t)
	return EngineStartRequest{
		Config: mihomoSessionTestLink,
		Opts: map[string]string{
			"proxyPort":         port,
			"geoAssetsDir":      home,
			"resolveExternalIp": "0",
			"livenessSec":       "300",
		},
	}, addr
}

const mihomoSessionTestLink = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:9?security=none&type=tcp#t"

// mihomo keeps cache.db open inside its home dir, so the dir outlives the test.
func mihomoSessionHome(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "glitch-mihomo-session-test")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func newMihomoSessionController(t *testing.T) *CoreController {
	t.Helper()
	x := &CoreController{}
	x.initEngineState()
	t.Cleanup(func() {
		x.stopStats()
		x.coreMutex.Lock()
		defer x.coreMutex.Unlock()
		x.endSessionLoops()
		x.mihomoStopLocked()
	})
	return x
}

func TestMihomoStop_TakenWhileALaterStartWaits(t *testing.T) {
	x := newMihomoSessionController(t)
	req, _ := mihomoProxyStart(t, mihomoSessionHome(t))
	queuedStopScenario(t, x, "mihomo", &x.mihomoSession, x.HandleMihomoStart, x.HandleMihomoStop, req)
}

func TestMihomoStart_ReplacesTheInstanceOfAStoppedSession(t *testing.T) {
	skipWhereMihomoRaces(t)
	x := newMihomoSessionController(t)
	home := mihomoSessionHome(t)
	reqA, addrA := mihomoProxyStart(t, home)
	reqB, addrB := mihomoProxyStart(t, home)

	replaceScenario(t, "mihomo", &x.mihomoSession, x.HandleMihomoStart, x.HandleMihomoStop, reqA, reqB)

	if !listens(addrB) {
		t.Fatal("B's proxy is not up")
	}
	if listens(addrA) {
		t.Fatal("A's proxy still answers")
	}
}

func TestMihomoStop_LeavesTheInstanceOfALaterStart(t *testing.T) {
	x := &CoreController{}
	x.mihomoSession.up(2)

	if err := x.mihomoStop(2); !errors.Is(err, errStopSuperseded) {
		t.Fatalf("stop of generation 2 over an instance started under 2: %v", err)
	}
	if !x.mihomoSession.running.Load() {
		t.Fatal("the stop marked the later session's engine stopped")
	}
}
