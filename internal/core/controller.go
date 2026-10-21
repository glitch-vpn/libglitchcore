package core

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

var globalController *CoreController

// statusVerbosity is the master log gate (FFI stream + stdout + every engine's
// own logger). Default -1 is silent everywhere, not even stdout.
//
//	-1 OFF (default) | 0 errors | 1 info+warn | 2 all
var statusVerbosity int32 = -1

var statusCallbackRegistered atomic.Bool

// inFFICall: while an FFI export runs, callbacks must be deferred (deferredStatus),
// never invoked synchronously - re-entry from a leaf FFI call.
var inFFICall atomic.Bool

const (
	xrayDefaultDnsServer    = "1.1.1.1"
	defaultTunMTU           = 1420
	defaultTunUDPTimeoutSec = 30
)

const (
	xrayAsset       = "xray.location.asset"
	xrayCert        = "xray.location.cert"
	xrayXudpBaseKey = "xray.xudp.basekey"
)

const (
	glitchCoreResultError   = 1
	glitchCoreResultSuccess = 0
)

// Status event codes. Engine id rides in the message payload.
const (
	StatsEvent = 300
	StatsError = 301
	// JSON serverinfo.Selection; re-emitted on change and on client reattach.
	ServerEvent = 302
	// JSON externalIPState: the addresses observed through the tunnel.
	IPEvent   = 303
	LogEvent  = 400
	LogError  = 401
	ConnEvent = 402

	EngineConnecting             = 500
	EngineConnected              = 501
	EngineError                  = 502
	EngineDisconnecting          = 503
	EngineDisconnected           = 504
	EngineAlreadyRunning         = 505
	EngineConflictOtherCore      = 506
	EngineStopRejectedNotRunning = 507
)

// CoreController: one engine at a time. Engine-typed fields live in embedded
// xrayState/awgState/bridgeState so an excluded engine links none of its packages.
type CoreController struct {
	coreMutex          sync.Mutex
	isXrayRunning      atomic.Bool
	isTun2socksRunning atomic.Bool
	currentAwgHandle   int
	isAwgRunning       atomic.Bool
	isMihomoRunning    atomic.Bool
	nextHandle         int
	statsMu            sync.Mutex
	statsTicker        *time.Ticker
	statsQuit          chan struct{}
	statsDone          chan struct{}
	awgIFName          string
	connectedAtUnixMs  atomic.Int64
	healthCheckQuit    chan struct{}
	xraySocksAddress   atomic.Value
	// atomic.Value holding []string: proxy outbound tags, stats summed over them.
	xrayOutboundTags atomic.Value
	// atomic.Int32 holding a liveness.State.
	linkState   atomic.Int32
	linkProbeMs atomic.Int64
	// loopsMu guards the quit/done pointers of the session loops (liveness,
	// selection watch). Held only across the pointer swap - never while
	// waiting on done, or a loop that needs coreMutex would deadlock a stop.
	loopsMu      sync.Mutex
	livenessQuit chan struct{}
	livenessDone chan struct{}
	// statsTransMu serializes whole start/stop transitions; statsMu still
	// guards the fields and is what the loop itself takes.
	statsTransMu sync.Mutex
	// sessionGen invalidates a start that raced a stop: the stop bumps it, and
	// the start's tail tears down anything it armed too late.
	sessionGen atomic.Int64

	// Last ServerEvent/IPEvent payloads, replayed to reattaching clients
	// (atomic.Value of string; "" = none).
	serverSelJSON atomic.Value
	ipStateJSON   atomic.Value
	// atomic.Value of ipResolveConfig; ipGen invalidates in-flight fetches
	// across engine restarts.
	ipResolve    atomic.Value
	ipGen        atomic.Int64
	ipFetchMu    sync.Mutex
	ipFetchBusy  bool
	ipFetchAgain bool
	selWatchQuit chan struct{}
	selWatchDone chan struct{}

	xrayState
	awgState
	bridgeState
}

func normalizedVersion(v string) string {
	t := strings.TrimSpace(v)
	if t == "" {
		return "unknown"
	}
	return t
}

func (x *CoreController) xrayRunning() bool {
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()
	return x.isXrayRunning.Load()
}

func (x *CoreController) awgRunning() bool {
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()
	return x.isAwgRunning.Load()
}

func (x *CoreController) emitStatus(code int32, message string) {
	x.updateConnectedAt(code)
	if carriesErrorText(code) {
		message = logfmt.Scrub(message)
	}
	if !statusCallbackRegistered.Load() {
		return
	}
	cbAny := statusSink.Load()
	callback, _ := cbAny.(func(int32, string))
	if callback == nil {
		return
	}
	if deferredStatus.offer(statusEvent{callback, code, message}, inFFICall.Load()) {
		return
	}
	callback(code, message)
}

// Lifecycle and stats-error texts wrap engine errors, and a parse error quotes
// the link it rejected. A JSON payload's free-text fields are scrubbed where
// they are built (log lines in emitLog, the IP errors in ipresolve).
func carriesErrorText(code int32) bool {
	switch code {
	case StatsError, EngineConnecting, EngineConnected, EngineError, EngineDisconnecting,
		EngineDisconnected, EngineAlreadyRunning, EngineConflictOtherCore, EngineStopRejectedNotRunning:
		return true
	default:
		return false
	}
}

func (x *CoreController) updateConnectedAt(code int32) {
	switch code {
	case EngineConnected, EngineAlreadyRunning:
		if x.connectedAtUnixMs.Load() == 0 {
			x.connectedAtUnixMs.Store(time.Now().UnixMilli())
		}
	case EngineDisconnecting, EngineDisconnected, EngineError:
		x.connectedAtUnixMs.Store(0)
	default:
		return
	}
}

func setEnvVar(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		logfmt.Errorf("[core][env] error setting env %s: %v", key, err)
	}
}

func applyStatusVerbosity(level int) {
	// -1 = OFF (nothing anywhere) is a valid level, not clamped to 0.
	if level < -1 {
		level = -1
	} else if level > 2 {
		level = 2
	}
	if useServiceIPC {
		if err := serviceSetVerbosity(level); err != nil {
			logfmt.Warnf("[IPC] set verbosity failed: %v", err)
		}
	}
	atomic.StoreInt32(&statusVerbosity, int32(level))
}

func applyTun2SocksConfig(mtu int, udpTimeoutSec int) {
	if mtu >= 1200 && mtu <= 1500 {
		_ = os.Setenv("GLITCH_TUN2SOCKS_MTU", strconv.Itoa(mtu))
	}
	if udpTimeoutSec >= 5 && udpTimeoutSec <= 300 {
		_ = os.Setenv("GLITCH_TUN2SOCKS_UDP_TIMEOUT_SEC", strconv.Itoa(udpTimeoutSec))
	}
}

func currentTun2SocksConfig() (int, int) {
	mtu := defaultTunMTU
	if s := os.Getenv("GLITCH_TUN2SOCKS_MTU"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 1200 && v <= 1500 {
			mtu = v
		}
	}

	udpTimeoutSec := defaultTunUDPTimeoutSec
	if s := os.Getenv("GLITCH_TUN2SOCKS_UDP_TIMEOUT_SEC"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 5 && v <= 300 {
			udpTimeoutSec = v
		}
	}

	return mtu, udpTimeoutSec
}
