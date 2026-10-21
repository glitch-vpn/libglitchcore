//go:build !no_xray

package core

import (
	"testing"

	xrayCommonLog "github.com/xtls/xray-core/common/log"
)

func TestEngineRegistry_HasXray(t *testing.T) {
	e, ok := engineRegistry["xray"]
	if !ok {
		t.Fatal(`engine "xray" not registered`)
	}
	if e.ID() != "xray" {
		t.Errorf(`engine "xray" reports ID() = %q`, e.ID())
	}
}

func TestXrayLogHandler_KeepsXraysSeverity(t *testing.T) {
	logs := captureLogs(t, 2)

	h := xrayLogHandler{}
	h.Handle(&xrayCommonLog.GeneralMessage{Severity: xrayCommonLog.Severity_Debug, Content: "[42] app/dns: querying"})
	h.Handle(&xrayCommonLog.GeneralMessage{Severity: xrayCommonLog.Severity_Info, Content: "proxy/vless: dial failed"})
	h.Handle(&xrayCommonLog.GeneralMessage{Severity: xrayCommonLog.Severity_Warning, Content: "app/observatory: probe error"})
	h.Handle(&xrayCommonLog.GeneralMessage{Severity: xrayCommonLog.Severity_Error, Content: "core: started"})

	want := []capturedLog{
		{LogEvent, "debug", "Xray", "[42] app/dns: querying"},
		{LogEvent, "info", "Xray", "proxy/vless: dial failed"},
		{LogEvent, "warn", "Xray", "app/observatory: probe error"},
		{LogError, "error", "Xray", "core: started"},
	}
	assertLogs(t, logs(), want)
}
