package core

import (
	"encoding/json"
	"log"
	"time"
)

const (
	ResultSuccess = glitchCoreResultSuccess
	ResultError   = glitchCoreResultError
)

// Set by the root package from -ldflags -X main.built* (link target stays main).
var (
	builtXrayCoreVersion  = "unknown"
	builtAmneziawgVersion = "unknown"
	builtMihomoVersion    = "unknown"
)

func SetBuiltVersions(xray, awg, mihomo string) {
	if xray != "" {
		builtXrayCoreVersion = xray
	}
	if awg != "" {
		builtAmneziawgVersion = awg
	}
	if mihomo != "" {
		builtMihomoVersion = mihomo
	}
}

// Filled by each engine's build-tagged init() - only linked engines appear.
var engineVersionGetters = map[string]func() string{}

func registerEngineVersion(key string, get func() string) { engineVersionGetters[key] = get }

func engineVersions() map[string]string {
	m := make(map[string]string, len(engineVersionGetters))
	for k, get := range engineVersionGetters {
		m[k] = normalizedVersion(get())
	}
	return m
}

func VersionsJSON() string {
	data, err := json.Marshal(engineVersions())
	if err != nil {
		return "{}"
	}
	return string(data)
}

func Capabilities() string { return coreCapabilities() }

func SetStatusSink(fn func(code int32, message string)) { setStatusSink(fn) }

func Initialize() {
	if globalController != nil {
		return
	}
	maybeStartPprof() // no-op unless GLITCH_PPROF_ADDR is set
	if useServiceIPC {
		ensureServiceIPC()
	}
	platformInit("")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(sinkWriter{})
	registerCoreLogHandler()
	applyMihomoLogLevel()
	controller := &CoreController{}
	controller.initEngineState()
	logSink = routeLogToFFI
	globalController = controller
}

// OnDartApiInit drops delivery state on hot restart until the new isolate re-registers.
func OnDartApiInit() {
	setStatusSink(nil)
	logSink = nil
	if globalController != nil {
		globalController.stopStats()
	}
}

func EngineStart(engineID string, req EngineStartRequest) int32 {
	if globalController == nil {
		return ResultError
	}
	return runFFICall(func() int32 {
		return globalController.engineStart(engineID, req)
	})
}

func EngineStop(engineID string) int32 {
	if globalController == nil {
		return ResultError
	}
	return runFFICall(func() int32 {
		return globalController.engineStop(engineID)
	})
}

func EngineIsRunning(engineID string) int32 {
	if globalController == nil {
		return ResultError
	}
	return globalController.engineIsRunning(engineID)
}

func ActiveEngineID() string {
	if globalController == nil {
		return ""
	}
	return globalController.activeEngineID()
}

// EngineTraffic for the Android notification JNI (no Dart isolate required).
func EngineTraffic() (rx, tx uint64, running bool) {
	if globalController == nil {
		return 0, 0, false
	}
	return globalController.readEngineTraffic()
}

func StartStats(interval time.Duration) int32 {
	if globalController == nil || interval <= 0 {
		return ResultError
	}
	globalController.startStats(interval)
	return ResultSuccess
}

func StopStats() int32 {
	if globalController == nil {
		return ResultError
	}
	globalController.stopStats()
	return ResultSuccess
}

func ApplyStatusVerbosity(level int) { applyStatusVerbosity(level) }

func ApplyConnInspector(enabled bool) { applyConnInspector(enabled) }

func SetEnv(key, value string) { setEnvVar(key, value) }

func ApplyTun2SocksConfig(mtu, udpTimeoutSec int) { applyTun2SocksConfig(mtu, udpTimeoutSec) }

// ApplyMemoryLimit: <=0 = unlimited.
func ApplyMemoryLimit(bytes int64) { applyMemoryLimit(bytes) }

func SetServiceIPC(enabled bool) { useServiceIPC = enabled }

func BuildModeService() bool { return buildModeService }

func RunServiceMain() { runServiceMain() }
