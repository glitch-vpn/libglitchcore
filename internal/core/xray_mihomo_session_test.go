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
