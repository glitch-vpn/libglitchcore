//go:build !no_xray && !no_mihomo

package core

import "testing"

// The other engine's start is refused while an engine's stop is still pending
// and accepted once it has finished. Both run in proxy mode, so no adapter
// exists here: what keeps a start from creating the desktop adapter while the
// last one's Close is running is desktopAdapterGate
// (xray_tun_adapter_test.go).
func TestEngineSwitch_NoStartBeforeTheOldEngineStopped(t *testing.T) {
	skipWhereMihomoRaces(t)
	home := mihomoSessionHome(t)
	t.Run("xray to mihomo", func(t *testing.T) {
		x := newMihomoSessionController(t)
		t.Cleanup(func() {
			x.coreMutex.Lock()
			defer x.coreMutex.Unlock()
			x.xrayStopLocked()
		})
		xrayReq, xrayAddr := xrayProxyStart(t)
		mihomoReq, mihomoAddr := mihomoProxyStart(t, home)
		life := recordLifecycle(t)

		if res := x.HandleXrayStart(xrayReq); res != glitchCoreResultSuccess {
			t.Fatalf("xray start = %d", res)
		}
		life.waitFor(t, EngineConnected, 1)

		releaseStop := holdStops(t, "xray")
		if res := x.HandleXrayStop(); res != glitchCoreResultSuccess {
			t.Fatalf("xray stop = %d", res)
		}
		if res := x.HandleMihomoStart(mihomoReq); res == glitchCoreResultSuccess {
			t.Fatal("mihomo started while xray's stop had not closed its adapter")
		}
		if life.count(EngineConflictOtherCore) != 1 || listens(mihomoAddr) {
			t.Fatalf("lifecycle %v, mihomo listening %v: want the start refused", life.snapshot(), listens(mihomoAddr))
		}
		releaseStop()
		life.waitFor(t, EngineDisconnected, 1)
		if x.xraySession.running.Load() || listens(xrayAddr) {
			t.Fatal("xray still runs after its stop was reported")
		}

		if res := x.HandleMihomoStart(mihomoReq); res != glitchCoreResultSuccess {
			t.Fatalf("mihomo start after xray stopped = %d", res)
		}
		life.waitFor(t, EngineConnected, 2)
	})

	t.Run("mihomo to xray", func(t *testing.T) {
		x := newMihomoSessionController(t)
		t.Cleanup(func() {
			x.coreMutex.Lock()
			defer x.coreMutex.Unlock()
			x.xrayStopLocked()
		})
		xrayReq, xrayAddr := xrayProxyStart(t)
		mihomoReq, mihomoAddr := mihomoProxyStart(t, home)
		life := recordLifecycle(t)

		if res := x.HandleMihomoStart(mihomoReq); res != glitchCoreResultSuccess {
			t.Fatalf("mihomo start = %d", res)
		}
		life.waitFor(t, EngineConnected, 1)

		releaseStop := holdStops(t, "mihomo")
		if res := x.HandleMihomoStop(); res != glitchCoreResultSuccess {
			t.Fatalf("mihomo stop = %d", res)
		}
		if res := x.HandleXrayStart(xrayReq); res == glitchCoreResultSuccess {
			t.Fatal("xray started while mihomo's stop had not closed its adapter")
		}
		if life.count(EngineConflictOtherCore) != 1 || listens(xrayAddr) {
			t.Fatalf("lifecycle %v, xray listening %v: want the start refused", life.snapshot(), listens(xrayAddr))
		}
		releaseStop()
		life.waitFor(t, EngineDisconnected, 1)
		if x.mihomoSession.running.Load() || listens(mihomoAddr) {
			t.Fatal("mihomo still runs after its stop was reported")
		}

		if res := x.HandleXrayStart(xrayReq); res != glitchCoreResultSuccess {
			t.Fatalf("xray start after mihomo stopped = %d", res)
		}
		life.waitFor(t, EngineConnected, 2)
	})
}
