//go:build !no_xray || (!no_mihomo && !no_awg)

package core

import (
	tun2socksLog "github.com/xjasonlyu/tun2socks/v2/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

// capTun2socksLogLevel holds tun2socks at warnings and worse: its info lines
// name every flow's full source and destination, which xray's own lines mask.
func capTun2socksLogLevel(level string) string {
	switch level {
	case "info", "debug", "trace":
		return "warn"
	default:
		return level
	}
}

// useTun2socksSink replaces the stderr logger tun2socks builds for itself on
// every engine start. Lines it writes before the swap stay on its own logger.
// It runs after engine.Start on the start goroutine, outside coreMutex: the
// swap must follow Start's own, and the logger is tun2socks's to guard.
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
	emitLog(tun2socksEntryLevel(e.Level), "tun2socks", e.Message)
	return nil
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
