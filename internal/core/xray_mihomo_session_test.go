//go:build !no_xray && !no_mihomo

package core

import "testing"

// A stop of one engine leaves Disconnected to a later start of the other, which
// is the server switch that crosses engines.
func TestXrayStop_LeavesDisconnectedToALaterMihomoStart(t *testing.T) {
	skipWhereMihomoRaces(t)
	x := newMihomoSessionController(t)
	reqA, _ := xrayProxyStart(t)
	reqB, _ := mihomoProxyStart(t, mihomoSessionHome(t))
	laterStartScenario(t, &x.xraySession, "xray", x.HandleXrayStart, x.HandleXrayStop, x.HandleMihomoStart,
		func() bool { return x.mihomoSession.runsSession(1) }, reqA, reqB)
}

// An earlier session's xray start still in flight does not hide the mihomo
// instance that is up: the replay reports the engine whose instance exists,
// whatever order the engines are looked at in.
func TestReplaySession_PrefersTheEngineThatIsUp(t *testing.T) {
	skipWhereMihomoRaces(t)
	x := newMihomoSessionController(t)
	life := recordLifecycle(t)
	x.xraySession.startRequested(0)
	t.Cleanup(func() { x.xraySession.startReturnedAt(0) })
	x.mihomoSession.up(x.sessionGen.Load())

	const replays = 50
	for range replays {
		if !x.replaySession() {
			t.Fatal("the replay saw no engine")
		}
	}
	if n := life.count(EngineConnected); n != replays {
		t.Fatalf("connected reported for %d of %d replays", n, replays)
	}
}
