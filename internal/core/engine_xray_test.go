//go:build !no_xray

package core

import (
	"strings"
	"sync/atomic"
	"testing"

	xrayAppLog "github.com/xtls/xray-core/app/log"
	xrayCommonLog "github.com/xtls/xray-core/common/log"
	xrayNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
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

func TestXrayLogHandler_MasksLinesNotTheInspector(t *testing.T) {
	logs := captureLogs(t, 2)
	prev := connInspectEnabled.Load()
	connInspectEnabled.Store(true)
	t.Cleanup(func() { connInspectEnabled.Store(prev) })

	masked := func(m xrayCommonLog.Message) xrayCommonLog.Message {
		return &xrayAppLog.MaskedMsgWrapper{Message: m, Mask4: 16, Mask6: 32}
	}
	h := xrayLogHandler{}
	h.Handle(masked(&xrayCommonLog.GeneralMessage{Severity: xrayCommonLog.Severity_Info, Content: "dialing to tcp:203.0.113.9:443"}))
	assertLogs(t, logs(), []capturedLog{{LogEvent, "info", "Xray", "dialing to tcp:203.0.*.*:443"}})

	var conns []string
	setStatusSink(func(code int32, message string) {
		if code == ConnEvent {
			conns = append(conns, message)
		}
	})
	h.Handle(masked(&xrayCommonLog.AccessMessage{
		From:   xrayNet.TCPDestination(xrayNet.ParseAddress("127.0.0.1"), 50000),
		To:     xrayNet.TCPDestination(xrayNet.ParseAddress("203.0.113.9"), 443),
		Status: xrayCommonLog.AccessAccepted,
		Detour: "tun2socks -> proxy",
	}))
	if len(conns) != 1 || !strings.Contains(conns[0], `"203.0.113.9"`) {
		t.Fatalf("inspector record = %v, want the unmasked host", conns)
	}
}

func TestXrayLogHandler_AccessRecordNeedsTheInspector(t *testing.T) {
	captureLogs(t, 2)
	prev := connInspectEnabled.Load()
	connInspectEnabled.Store(false)
	t.Cleanup(func() { connInspectEnabled.Store(prev) })
	var conns []string
	setStatusSink(func(code int32, message string) {
		if code == ConnEvent {
			conns = append(conns, message)
		}
	})

	xrayLogHandler{}.Handle(&xrayCommonLog.AccessMessage{
		From:   xrayNet.TCPDestination(xrayNet.ParseAddress("127.0.0.1"), 50000),
		To:     xrayNet.TCPDestination(xrayNet.ParseAddress("203.0.113.9"), 443),
		Status: xrayCommonLog.AccessAccepted,
		Detour: "tun2socks >> proxy",
	})
	if len(conns) != 0 {
		t.Fatalf("an access record became a ConnEvent with the inspector off: %v", conns)
	}
}

func TestXrayLogHandler_SeverityFollowsVerbosity(t *testing.T) {
	prev := atomic.LoadInt32(&statusVerbosity)
	t.Cleanup(func() { atomic.StoreInt32(&statusVerbosity, prev) })
	for verbosity, want := range map[int32]xrayCommonLog.Severity{
		-1: xrayCommonLog.Severity_Unknown,
		0:  xrayCommonLog.Severity_Error,
		1:  xrayCommonLog.Severity_Info,
		2:  xrayCommonLog.Severity_Debug,
	} {
		atomic.StoreInt32(&statusVerbosity, verbosity)
		if got := (xrayLogHandler{}).Severity(); got != want {
			t.Errorf("verbosity %d: severity = %v, want %v", verbosity, got, want)
		}
	}
}

func TestXrayLogHandler_AccessLineIsADebugLogLine(t *testing.T) {
	logs := captureLogs(t, 2)
	xrayLogHandler{}.Handle(&xrayCommonLog.AccessMessage{
		From:   xrayNet.TCPDestination(xrayNet.ParseAddress("127.0.0.1"), 50000),
		To:     xrayNet.TCPDestination(xrayNet.ParseAddress("203.0.113.9"), 443),
		Status: xrayCommonLog.AccessAccepted,
		Detour: "tun2socks -> proxy",
	})
	assertLogs(t, logs(), []capturedLog{{LogEvent, "debug", "Xray", "from tcp:127.0.*.*:50000 accepted tcp:203.0.*.*:443 [tun2socks -> proxy]"}})
}

func TestSniffedTarget_NamesTheDomainRouteOnlySniffingFound(t *testing.T) {
	dest := xrayNet.TCPDestination(xrayNet.ParseAddress("203.0.113.9"), 443)
	outbound := &session.Outbound{}
	target := sniffedTarget{dest: dest, outbound: outbound}
	if got := target.String(); got != "tcp:203.0.113.9:443" {
		t.Fatalf("before sniffing = %q", got)
	}
	outbound.RouteTarget = xrayNet.TCPDestination(xrayNet.ParseAddress("ads.example"), 443)
	if got := target.String(); got != "tcp:ads.example:443" {
		t.Fatalf("route-only sniffing = %q", got)
	}
	outbound.Target = xrayNet.TCPDestination(xrayNet.ParseAddress("fake.example"), 443)
	if got := target.String(); got != "tcp:fake.example:443" {
		t.Fatalf("fake-IP result = %q", got)
	}
}
