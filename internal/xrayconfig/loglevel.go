package xrayconfig

const (
	tun2socksLogWarnLevel   = "warn"
	tun2socksLogInfoLevel   = "info"
	tun2socksLogDebugLevel  = "debug"
	tun2socksLogErrorLevel  = "error"
	tun2socksLogSilentLevel = "silent"
)

// xray has no "silent": a level it does not know reads as warning. Its "none"
// turns the access logger off with the error one, and the connection
// inspector reads the access records, so the quietest level that keeps them
// is "error".
const (
	xrayLogWarnLevel  = "warning"
	xrayLogInfoLevel  = "info"
	xrayLogDebugLevel = "debug"
	xrayLogErrorLevel = "error"
)

// LogLevels maps the connect logLevel to the levels xray and tun2socks run at.
// With logging off both are as quiet as they get. With it on, xray runs at
// warning when the caller asked for none (0), while tun2socks stays silent
// then: its lines carry full destination addresses, which xray masks.
func LogLevels(requested int, loggingOn bool) (xrayLevel, tun2socksLevel string) {
	if !loggingOn {
		return xrayLogErrorLevel, tun2socksLogSilentLevel
	}
	switch requested {
	case 1:
		return xrayLogWarnLevel, tun2socksLogWarnLevel
	case 2:
		return xrayLogInfoLevel, tun2socksLogInfoLevel
	case 3:
		return xrayLogDebugLevel, tun2socksLogDebugLevel
	case 4:
		return xrayLogErrorLevel, tun2socksLogErrorLevel
	case 0:
		return xrayLogWarnLevel, tun2socksLogSilentLevel
	}
	return xrayLogErrorLevel, tun2socksLogSilentLevel
}
