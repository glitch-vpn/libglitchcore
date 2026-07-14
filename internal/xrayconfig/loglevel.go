package xrayconfig

const (
	tun2socksLogWarnLevel   = "warn"
	tun2socksLogInfoLevel   = "info"
	tun2socksLogDebugLevel  = "debug"
	tun2socksLogErrorLevel  = "error"
	tun2socksLogFatalLevel  = "fatal"
	tun2socksLogPanicLevel  = "panic"
	tun2socksLogTraceLevel  = "trace"
	tun2socksLogSilentLevel = "silent"
)

const (
	xrayLogWarnLevel   = "warn"
	xrayLogInfoLevel   = "info"
	xrayLogDebugLevel  = "debug"
	xrayLogErrorLevel  = "error"
	xrayLogSilentLevel = "silent"
)

func LogLevels(level int) (xrayLevel, tun2socksLevel string) {
	switch level {
	case 0:
		return xrayLogSilentLevel, tun2socksLogSilentLevel
	case 1:
		return xrayLogWarnLevel, tun2socksLogWarnLevel
	case 2:
		return xrayLogInfoLevel, tun2socksLogInfoLevel
	case 3:
		return xrayLogDebugLevel, tun2socksLogDebugLevel
	case 4:
		return xrayLogErrorLevel, tun2socksLogErrorLevel
	}
	return xrayLogSilentLevel, tun2socksLogSilentLevel
}

// CapTun2socksLogLevel caps the tun2socks log level so that the proxy URL
// (which carries ephemeral SOCKS credentials) is never logged. tun2socks logs
// engine.Key.Proxy at info level, so info/debug/trace are clamped to warn.
func CapTun2socksLogLevel(level string) string {
	switch level {
	case tun2socksLogInfoLevel, tun2socksLogDebugLevel, tun2socksLogTraceLevel:
		return tun2socksLogWarnLevel
	default:
		return level
	}
}
