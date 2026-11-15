//go:build !no_xray

package core

import (
	"regexp"

	tun2socksLog "github.com/xjasonlyu/tun2socks/v2/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

// capTun2socksLogLevel holds tun2socks at warnings and worse: its info lines
// name every flow's full source and destination, which xray's own lines mask.
// Its warnings name a flow's destination too, on a dial it could not make:
// maskFlowAddresses takes those out on the way to the sink.
func capTun2socksLogLevel(level string) string {
	switch level {
	case "info", "debug", "trace":
		return "warn"
	default:
		return level
	}
}

// useTun2socksSink replaces the stderr logger tun2socks builds for itself on
// every engine start. Lines it writes before the swap, the [STACK] one naming
// the proxy URL among them, stay on its own logger: hence capTun2socksLogLevel.
// It runs right after engine.Start, whose own swap it must follow; tun2socks
// guards the swap against the stack's goroutines reading the logger.
func useTun2socksSink(level string) {
	parsed, err := tun2socksLog.ParseLevel(level)
	if err != nil || parsed == tun2socksLog.SilentLevel {
		tun2socksLog.SetLogger(zap.NewNop())
		return
	}
	tun2socksLog.SetLogger(zap.New(tun2socksSinkCore{LevelEnabler: parsed}))
}

type tun2socksSinkCore struct {
	zapcore.LevelEnabler
}

func (c tun2socksSinkCore) With([]zapcore.Field) zapcore.Core { return c }

func (c tun2socksSinkCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) && logEnabled(tun2socksEntryLevel(e.Level)) {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c tun2socksSinkCore) Write(e zapcore.Entry, _ []zapcore.Field) error {
	emitLog(tun2socksEntryLevel(e.Level), "tun2socks", maskFlowAddresses(e.Message))
	return nil
}

var flowAddress = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}:\d+|\[[0-9A-Fa-f:.]+\]:\d+`)

// maskFlowAddresses replaces every socket address in a tun2socks line: the
// shareable log names no flow's destination.
func maskFlowAddresses(line string) string {
	return flowAddress.ReplaceAllLiteralString(line, "<addr>")
}

func (tun2socksSinkCore) Sync() error { return nil }

func tun2socksEntryLevel(l zapcore.Level) logfmt.Level {
	switch {
	case l <= zapcore.DebugLevel:
		return logfmt.Debug
	case l == zapcore.InfoLevel:
		return logfmt.Info
	case l == zapcore.WarnLevel:
		return logfmt.Warn
	case l == zapcore.ErrorLevel:
		return logfmt.Error
	default:
		return logfmt.Fatal
	}
}
