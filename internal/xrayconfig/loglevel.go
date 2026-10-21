package xrayconfig

const (
	tun2socksLogWarnLevel   = "warn"
	tun2socksLogInfoLevel   = "info"
	tun2socksLogDebugLevel  = "debug"
	tun2socksLogErrorLevel  = "error"
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
