package core

import (
	"log"
	"os"
	"strings"
	"sync/atomic"

	"github.com/glitch-vpn/libglitchcore/internal/conninspect"
	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

var logSink func(string)

// connInspectEnabled gates the inspector: off = xray access-log lines are
// dropped as per-connection noise; on = each becomes a ConnEvent instead.
var connInspectEnabled atomic.Bool

func shouldEmitStatusMessage(s string) bool {
	return logfmt.ShouldEmit(atomic.LoadInt32(&statusVerbosity), s)
}

// applyConnInspector forwards to the service in Windows library mode - the
// engines (and thus their access log / tracker) run there.
func applyConnInspector(enabled bool) {
	if useServiceIPC {
		if err := serviceSetConnInspector(enabled); err != nil {
			log.Printf("[IPC] set conn inspector failed: %v", err)
		}
	}
	connInspectEnabled.Store(enabled)
}

func (x *CoreController) emitConn(rec conninspect.Record) {
	if x == nil || !connInspectEnabled.Load() || logSink == nil || inFFICall.Load() {
		return
	}
	if js := rec.JSON(); js != "" {
		x.emitStatus(ConnEvent, js)
	}
}

// handleCoreLogLine turns an xray access-log line into a ConnEvent (when the
// inspector is on) instead of a log entry; everything else is JSON-formatted,
// mirrored to stdout, and sent through logSink under the verbosity filter.
func handleCoreLogLine(raw string) {
	if a, ok := logfmt.ParseAccess(raw); ok {
		if globalController != nil {
			globalController.emitConn(conninspect.Record{
				Engine:   "xray",
				Src:      a.Src,
				Status:   a.Status,
				Network:  a.Network,
				Host:     a.Host,
				Port:     a.Port,
				Inbound:  a.Inbound,
				Outbound: a.Outbound,
			})
		}
		return
	}

	component, msg := logfmt.Component(raw)
	if len(strings.TrimSpace(msg)) == 0 {
		return
	}
	if !shouldEmitStatusMessage(msg) {
		return
	}
	level := logfmt.InferLevel(msg)
	line := logfmt.BuildJSON(level, component, msg)
	_, _ = os.Stdout.Write(append([]byte(line), '\n'))
	if logSink != nil && !inFFICall.Load() {
		logSink(line)
	}
}

// routeLogToFFI is the default logSink; it routes through emitStatus so the
// callback-registered guard and inFFICall deferral apply.
func routeLogToFFI(msg string) {
	if !shouldEmitStatusMessage(msg) {
		return
	}
	if globalController == nil {
		return
	}
	code := int32(LogEvent)
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "error") || strings.Contains(lower, "failed") || strings.Contains(lower, "panic") || strings.Contains(lower, "fatal") {
		code = int32(LogError)
	}
	globalController.emitStatus(code, msg)
}

type sinkWriter struct{}

func (sw sinkWriter) Write(p []byte) (n int, err error) {
	raw := strings.TrimRight(string(p), "\n")
	if len(raw) == 0 {
		return len(p), nil
	}
	handleCoreLogLine(raw)
	return len(p), nil
}
