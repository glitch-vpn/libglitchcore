//go:build !no_xray

package core

import (
	"sync/atomic"
	"testing"

	xrayCommonLog "github.com/xtls/xray-core/common/log"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
)

// xray asks its handler for the severity before it builds a message; the
// answer follows the verbosity after the instance is built, in every session.
func TestXrayInstance_SeverityFollowsVerbosityAcrossSessions(t *testing.T) {
	captureLogs(t, -1)
	x := &CoreController{}
	for session := 0; session < 2; session++ {
		res, err := xrayconfig.BuildConfig([]string{bridgeTestVlessLink}, xrayconfig.BalancerOptions{}, routing.Profile{Mode: routing.ModeProxyAll}, xrayconfig.InstanceLogLevel)
		if err != nil {
			t.Fatal(err)
		}
		built, err := res.Config.Build()
		if err != nil {
			t.Fatal(err)
		}
		inst, err := x.newXrayInstance(built)
		if err != nil {
			t.Fatal(err)
		}
		for verbosity, want := range map[int32]xrayCommonLog.Severity{
			-1: xrayCommonLog.Severity_Unknown,
			0:  xrayCommonLog.Severity_Error,
			1:  xrayCommonLog.Severity_Info,
			2:  xrayCommonLog.Severity_Debug,
		} {
			atomic.StoreInt32(&statusVerbosity, verbosity)
			if got := xrayCommonLog.GetSeverity(); got != want {
				t.Errorf("session %d, verbosity %d: severity = %v, want %v", session, verbosity, got, want)
			}
		}
		_ = inst.Close()
		x.endXrayLife()
		registerCoreLogHandler()
	}
}
