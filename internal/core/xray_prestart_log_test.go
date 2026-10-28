//go:build !no_xray

package core

import (
	"strings"
	"sync/atomic"
	"testing"

	xrayCommonLog "github.com/xtls/xray-core/common/log"
	xrayCore "github.com/xtls/xray-core/core"

	"github.com/glitch-vpn/libglitchcore/internal/pinger"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
)

// Lines xray writes before any instance exists, the geodata reload and the
// config build, follow the core's verbosity and its scrubbing.
func TestRegisterCoreLogHandler_TakesXrayLinesBeforeAnInstance(t *testing.T) {
	logs := captureLogs(t, -1)
	registerCoreLogHandler()
	link := "vless://11111111-2222-3333-4444-555555555555@example.test:443?security=reality&sni=hidden.test#n"
	record := func() {
		xrayCommonLog.Record(&xrayCommonLog.GeneralMessage{Severity: xrayCommonLog.Severity_Warning, Content: "infra/conf: " + link})
	}

	record()
	if n := len(logs()); n != 0 {
		t.Fatalf("logging off still delivered %d lines", n)
	}

	atomic.StoreInt32(&statusVerbosity, 2)
	record()
	got := logs()
	if len(got) != 1 || got[0].Component != "Xray" {
		t.Fatalf("lines = %+v, want one from Xray", got)
	}
	if strings.Contains(got[0].Message, "11111111-2222") || strings.Contains(got[0].Message, "hidden.test") {
		t.Fatalf("line carries the link: %q", got[0].Message)
	}
}

func newXrayInstanceForLogTest(t *testing.T) *xrayCore.Instance {
	t.Helper()
	res, err := xrayconfig.BuildConfig([]string{bridgeTestVlessLink}, xrayconfig.BalancerOptions{}, xrayconfig.RoutingProfile{}, "error")
	if err != nil {
		t.Fatal(err)
	}
	built, err := res.Config.Build()
	if err != nil {
		t.Fatal(err)
	}
	inst, err := xrayCore.New(built)
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

// An instance registers its own handler and leaves it after it closes; the
// next session's geodata reload and config build must reach the core's again.
func TestXrayInstanceClose_LeavesTheCoreLogHandlerRegistered(t *testing.T) {
	for name, closeInstance := range map[string]func(x *CoreController){
		"stop":     func(x *CoreController) { x.xrayStopLocked() },
		"rollback": func(x *CoreController) { x.xrayRollback() },
	} {
		t.Run(name, func(t *testing.T) {
			logs := captureLogs(t, -1)
			x := &CoreController{}
			x.initEngineState()
			x.xrayCoreInstance = newXrayInstanceForLogTest(t)
			x.xraySession.running.Store(true)
			x.coreMutex.Lock()
			closeInstance(x)
			x.coreMutex.Unlock()

			record := func() {
				xrayCommonLog.Record(&xrayCommonLog.GeneralMessage{Severity: xrayCommonLog.Severity_Warning, Content: "dial 203.0.113.77:443"})
			}
			record()
			if n := len(logs()); n != 0 {
				t.Fatalf("logging off delivered %d lines", n)
			}
			atomic.StoreInt32(&statusVerbosity, 2)
			record()
			got := logs()
			if len(got) != 1 {
				t.Fatalf("after the close: %d lines, want 1", len(got))
			}
			if strings.Contains(got[0].Message, "113.77") {
				t.Fatalf("line keeps the whole address: %q", got[0].Message)
			}
		})
	}
}

// A ping builds and closes an xray instance while a session runs; the
// session's lines must still reach the core's handler afterwards.
func TestPingDuringAXraySession_KeepsTheSessionsLogHandler(t *testing.T) {
	logs := captureLogs(t, 2)
	registerCoreLogHandler()
	session := newXrayInstanceForLogTest(t)
	t.Cleanup(func() { _ = session.Close(); registerCoreLogHandler() })

	pinger.Measure(pinger.Request{
		Engine:    "xray",
		Links:     []string{bridgeTestVlessLink},
		ProbeURL:  "http://198.51.100.1/",
		TimeoutMs: 800,
	})

	xrayCommonLog.Record(&xrayCommonLog.GeneralMessage{Severity: xrayCommonLog.Severity_Error, Content: "session marker"})
	if got := logs(); len(got) != 1 || got[0].Message != "session marker" {
		t.Fatalf("lines after the ping = %+v, want the session's marker", got)
	}
}
