package xrayconfig

const (
	tun2socksLogWarnLevel   = "warn"
	tun2socksLogInfoLevel   = "info"
	tun2socksLogDebugLevel  = "debug"
	tun2socksLogErrorLevel  = "error"
	tun2socksLogSilentLevel = "silent"
)

// InstanceLogLevel is the level an xray instance's config carries. It only
// matters while NewSession builds the instance: the core's handler replaces
// the instance's own right after and gates xray's lines from the live
// verbosity (xrayLogHandler.Severity).
const InstanceLogLevel = "debug"

// Tun2socksLogLevel maps the connect logLevel to the level tun2socks runs at.
// With logging off it is silent. With it on, it stays silent when the caller
// asked for none (0): its lines carry full destination addresses, which xray
// masks.
func Tun2socksLogLevel(requested int, loggingOn bool) string {
	if !loggingOn {
		return tun2socksLogSilentLevel
	}
	switch requested {
	case 1:
		return tun2socksLogWarnLevel
	case 2:
		return tun2socksLogInfoLevel
	case 3:
		return tun2socksLogDebugLevel
	case 4:
		return tun2socksLogErrorLevel
	}
	return tun2socksLogSilentLevel
}
