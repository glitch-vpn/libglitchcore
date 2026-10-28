package xrayconfig

import (
	"testing"

	xraylog "github.com/xtls/xray-core/app/log"
	clog "github.com/xtls/xray-core/common/log"
)

func TestLogLevels(t *testing.T) {
	cases := []struct {
		requested    int
		loggingOn    bool
		wantSeverity clog.Severity
		wantTun2     string
	}{
		{0, false, clog.Severity_Error, "silent"},
		{3, false, clog.Severity_Error, "silent"},
		{0, true, clog.Severity_Warning, "silent"},
		{1, true, clog.Severity_Warning, "warn"},
		{2, true, clog.Severity_Info, "info"},
		{3, true, clog.Severity_Debug, "debug"},
		{4, true, clog.Severity_Error, "error"},
	}
	for _, tc := range cases {
		xrayLevel, tun2 := LogLevels(tc.requested, tc.loggingOn)
		if tun2 != tc.wantTun2 {
			t.Fatalf("LogLevels(%d, %v) tun2socks = %q, want %q", tc.requested, tc.loggingOn, tun2, tc.wantTun2)
		}
		res, err := BuildConfig([]string{dnsTestLink}, BalancerOptions{}, RoutingProfile{}, xrayLevel)
		if err != nil {
			t.Fatalf("BuildConfig: %v", err)
		}
		built := res.Config.LogConfig.Build()
		if built.ErrorLogLevel != tc.wantSeverity {
			t.Fatalf("LogLevels(%d, %v): xray severity = %v, want %v", tc.requested, tc.loggingOn, built.ErrorLogLevel, tc.wantSeverity)
		}
		// The inspector reads the access records: that logger stays on.
		if built.AccessLogType != xraylog.LogType_Console || built.ErrorLogType != xraylog.LogType_Console {
			t.Fatalf("LogLevels(%d, %v): loggers = access %v error %v, want console", tc.requested, tc.loggingOn, built.AccessLogType, built.ErrorLogType)
		}
	}
}
