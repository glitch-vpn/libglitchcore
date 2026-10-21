package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/glitch-vpn/libglitchcore/internal/conninspect"
	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

// connInspectEnabled gates the inspector: off = xray access-log lines are
// dropped as per-connection noise; on = each becomes a ConnEvent instead.
var connInspectEnabled atomic.Bool

// applyConnInspector forwards to the service in Windows library mode - the
// engines (and thus their access log / tracker) run there.
func applyConnInspector(enabled bool) {
	if useServiceIPC {
		if err := serviceSetConnInspector(enabled); err != nil {
			logfmt.Warnf("[IPC] set conn inspector failed: %v", err)
		}
	}
	connInspectEnabled.Store(enabled)
}

func (x *CoreController) emitConn(rec conninspect.Record) {
	if x == nil || !connInspectEnabled.Load() {
		return
	}
	if js := rec.JSON(); js != "" {
		x.emitStatus(ConnEvent, js)
	}
}

func logEnabled(level logfmt.Level) bool {
	return logfmt.Passes(atomic.LoadInt32(&statusVerbosity), level)
}

// emitLog is the one sink for every engine's lines and the core's own: the
// level is the one its writer reported, and it alone decides the verbosity
// gate and LogEvent versus LogError. The text is scrubbed before the payload
// is built: a redaction inside JSON could cut an escape in half.
func emitLog(level logfmt.Level, component, message string) {
	if !logEnabled(level) || strings.TrimSpace(message) == "" {
		return
	}
	line := logfmt.BuildJSON(level, logfmt.Scrub(component), logfmt.Scrub(message))
	_, _ = os.Stdout.Write(append([]byte(line), '\n'))
	if globalController == nil {
		return
	}
	code := int32(LogEvent)
	if level.IsError() {
		code = LogError
	}
	globalController.emitStatus(code, line)
}

// relayedLogPasses holds a log line relayed from the service to this
// process's own gate: the service's verbosity is whatever its last client set.
func relayedLogPasses(code int32, payload string) bool {
	if code != LogEvent && code != LogError {
		return true
	}
	var line struct {
		Level logfmt.Level `json:"level"`
	}
	if err := json.Unmarshal([]byte(payload), &line); err != nil {
		return false
	}
	return logEnabled(line.Level)
}

// emitLogf formats only once the line has passed the gate: engines call it on
// paths where a dropped line must cost nothing.
func emitLogf(level logfmt.Level, component, format string, args ...any) {
	if !logEnabled(level) {
		return
	}
	emitLog(level, component, fmt.Sprintf(format, args...))
}

// sinkWriter is the standard log package's output: the core's own lines
// (logfmt.Warnf and logfmt.Errorf carry their level) and whatever a dependency
// writes there.
type sinkWriter struct{}

func (sinkWriter) Write(p []byte) (n int, err error) {
	raw := strings.TrimRight(string(p), "\n")
	if len(raw) == 0 {
		return len(p), nil
	}
	level, component, msg := logfmt.SplitLine(raw)
	emitLog(level, component, msg)
	return len(p), nil
}
