package xrayconfig

import (
	"testing"

	xraylog "github.com/xtls/xray-core/app/log"
	clog "github.com/xtls/xray-core/common/log"
)

func TestTun2socksLogLevel(t *testing.T) {
	cases := []struct {
		requested    int
		loggingOn    bool
		wantSeverity clog.Severity
		wantTun2     string
	}{
		{0, false, clog.Severity_Debug, "silent"},
		{3, false, clog.Severity_Debug, "silent"},
		{0, true, clog.Severity_Debug, "silent"},
		{1, true, clog.Severity_Debug, "warn"},
		{2, true, clog.Severity_Debug, "info"},
		{3, true, clog.Severity_Debug, "debug"},
		{4, true, clog.Severity_Debug, "error"},
	}
	for _, tc := range cases {
		tun2 := Tun2socksLogLevel(tc.requested, tc.loggingOn)
		if tun2 != tc.wantTun2 {
			t.Fatalf("LogLevels(%d, %v) tun2socks = %q, want %q", tc.requested, tc.loggingOn, tun2, tc.wantTun2)
		}
		res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, RoutingProfile{}, InstanceLogLevel)
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
		}
		built := res.Config.LogConfig.Build()
		if built.ErrorLogLevel != tc.wantSeverity {
			t.Fatalf("LogLevels(%d, %v): xray severity = %v, want %v", tc.requested, tc.loggingOn, built.ErrorLogLevel, tc.wantSeverity)
		}
		// The core's handler gates the lines, so xray always runs at debug.
		// The inspector reads the access records: that logger stays on.
		if built.AccessLogType != xraylog.LogType_Console || built.ErrorLogType != xraylog.LogType_Console {
			t.Fatalf("LogLevels(%d, %v): loggers = access %v error %v, want console", tc.requested, tc.loggingOn, built.AccessLogType, built.ErrorLogType)
		}
	}
}
