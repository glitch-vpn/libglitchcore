// Package main is the CGo/FFI shell; all logic lives in internal/core.
package main

/*
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#if defined(_WIN32)
#include <windows.h>
#endif
#include "dart_api_dl.h"

static inline int init_dart_api_dl(void* data) {
    return (int)Dart_InitializeApiDL(data);
}

// Port-based status delivery via Dart_PostCObject_DL.
// When the receiving isolate dies (hot restart), Dart_PostCObject_DL
// returns false instead of crashing - unlike NativeCallable trampolines.
static int64_t g_dart_port = 0;

static inline void register_status_port(int64_t port) {
    g_dart_port = port;
}

// Post [code, message] to Dart ReceivePort. Returns false if port is dead.
static inline bool post_status_to_port(int32_t code, const char* msg) {
    if (g_dart_port == 0) return false;

    Dart_CObject c_code;
    c_code.type = Dart_CObject_kInt32;
    c_code.value.as_int32 = code;

    Dart_CObject c_msg;
    c_msg.type = Dart_CObject_kString;
    c_msg.value.as_string = (char*)msg;

    Dart_CObject* elements[2] = {&c_code, &c_msg};

    Dart_CObject c_array;
    c_array.type = Dart_CObject_kArray;
    c_array.value.as_array.length = 2;
    c_array.value.as_array.values = elements;

    return Dart_PostCObject_DL(g_dart_port, &c_array);
}
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
	"unsafe"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	"github.com/glitch-vpn/libglitchcore/internal/pinger"
)

// Injected via -ldflags "-X main.built*"; forwarded to core in init.
var (
	builtXrayCoreVersion  = "unknown"
	builtAmneziawgVersion = "unknown"
	builtMihomoVersion    = "unknown"
)

func init() {
	core.SetBuiltVersions(builtXrayCoreVersion, builtAmneziawgVersion, builtMihomoVersion)
}

//export RegisterStatusPort
func RegisterStatusPort(port C.int64_t) {
	C.register_status_port(port)
	if port == 0 {
		core.SetStatusSink(nil)
		return
	}
	core.SetStatusSink(func(code int32, message string) {
		cMsg := C.CString(message)
		ok := bool(C.post_status_to_port(C.int32_t(code), cMsg))
		C.free(unsafe.Pointer(cMsg))
		if !ok {
			// Port dead (isolate restarted) - disable to avoid future attempts
			C.register_status_port(0)
			core.SetStatusSink(nil)
		}
	})
}

//export FreeStatusMessage
func FreeStatusMessage(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

//export GetCoreVersions
func GetCoreVersions() *C.char {
	return C.CString(core.VersionsJSON())
}

//export CoreCapabilities
func CoreCapabilities() *C.char {
	// Caller frees via FreeStatusMessage (same contract as GetCoreVersions).
	return C.CString(core.Capabilities())
}

//export MeasurePings
func MeasurePings(cRequestJSON *C.char) *C.char {
	// Caller frees via FreeStatusMessage.
	var req pinger.Request
	if err := json.Unmarshal([]byte(C.GoString(cRequestJSON)), &req); err != nil {
		return C.CString(fmt.Sprintf(`{"error":%q}`, err.Error()))
	}
	data, err := json.Marshal(pinger.Measure(req))
	if err != nil {
		return C.CString(fmt.Sprintf(`{"error":%q}`, err.Error()))
	}
	return C.CString(string(data))
}

//export EngineStart
func EngineStart(cEngineID *C.char, cRequestJSON *C.char) C.int {
	engineID := C.GoString(cEngineID)
	var req core.EngineStartRequest
	if err := json.Unmarshal([]byte(C.GoString(cRequestJSON)), &req); err != nil {
		log.Printf("[Engine] start rejected: bad request for %q: %v", engineID, err)
		return C.int(core.ResultError)
	}
	return C.int(core.EngineStart(engineID, req))
}

//export EngineStop
func EngineStop(cEngineID *C.char) C.int {
	return C.int(core.EngineStop(C.GoString(cEngineID)))
}

//export EngineIsRunning
func EngineIsRunning(cEngineID *C.char) C.int {
	return C.int(core.EngineIsRunning(C.GoString(cEngineID)))
}

//export ActiveEngine
func ActiveEngine() *C.char {
	// Empty string when idle. Caller frees via FreeStatusMessage.
	return C.CString(core.ActiveEngineID())
}

//export InitializeController
func InitializeController() {
	core.Initialize()
}

//export SetStatusVerbosity
func SetStatusVerbosity(level C.int) {
	core.ApplyStatusVerbosity(int(level))
	log.Printf("[LOG] Logs verbosity set to: %d", level)
}

//export SetConnInspector
func SetConnInspector(enabled C.int) {
	core.ApplyConnInspector(enabled != 0)
	log.Printf("[LOG] Connection inspector: %v", enabled != 0)
}

//export InitDartApiDL
func InitDartApiDL(data unsafe.Pointer) C.int {
	// Hot restart: a new isolate is initializing - drop the old (dead) port;
	// the new isolate re-registers via RegisterStatusPort.
	C.register_status_port(0)
	core.OnDartApiInit()
	return C.int(C.init_dart_api_dl(data))
}

//export SetEnvVar
func SetEnvVar(key *C.char, value *C.char) {
	if key == nil {
		return
	}
	goKey := C.GoString(key)
	if value == nil {
		_ = os.Unsetenv(goKey)
		return
	}
	core.SetEnv(goKey, C.GoString(value))
}

//export SetSocksReadyTimeoutSec
func SetSocksReadyTimeoutSec(sec C.int) {
	v := int(sec)
	if v <= 0 || v > 60 {
		return
	}
	_ = os.Setenv("GLITCH_SOCKS_READY_TIMEOUT_SEC", strconv.Itoa(v))
}

//export SetTun2SocksConfig
func SetTun2SocksConfig(mtu C.int, udpTimeoutSec C.int) {
	core.ApplyTun2SocksConfig(int(mtu), int(udpTimeoutSec))
}

//export SetMemoryLimit
func SetMemoryLimit(bytes C.int64_t) {
	core.ApplyMemoryLimit(int64(bytes))
}

//export SetUseServiceIPC
func SetUseServiceIPC(enabled C.int) {
	core.SetServiceIPC(enabled != 0)
}

//export ListenStats
func ListenStats(delayMs C.int) C.int {
	return C.int(core.StartStats(time.Duration(delayMs) * time.Millisecond))
}

//export StopStats
func StopStats() C.int {
	return C.int(core.StopStats())
}

func main() {
	if core.BuildModeService() {
		core.RunServiceMain()
	}
}
