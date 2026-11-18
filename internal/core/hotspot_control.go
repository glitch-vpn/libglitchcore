package core

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

// PrepareHotspot repairs ICS's stale state before a hotspot starts. It acts
// where the process is elevated: the service, or this process when the core
// runs in-process.
func PrepareHotspot() int32 {
	if useServiceIPC {
		code, err := servicePrepareHotspot()
		if err != nil {
			logfmt.Warnf("[hotspot] service prepare failed: %v", err)
			return ResultError
		}
		return code
	}
	return prepareHotspotOnce()
}

// The repair restarts a service and takes up to a minute, so it is one at a
// time, and the service runs it off its command pipe: a command there returns
// promptly, and the client asks again, with the token it started with, until
// the repair is done.
var (
	// prepareHotspotFunc is what the repair runs; a test replaces it.
	prepareHotspotFunc = prepareHotspot
	prepareMu          sync.Mutex
	prepareFlight      struct {
		mu       sync.Mutex
		token    string // the poll sequence that started the current or last repair
		running  bool
		finished bool
		result   int32
	}
)

func prepareHotspotOnce() int32 {
	prepareMu.Lock()
	defer prepareMu.Unlock()
	return prepareHotspotFunc()
}

// pollPrepareHotspot answers whether the repair that the token's poll sequence
// started is done and with what, and gives that answer once. A sequence that
// finds another's repair under way waits for it and then starts its own; a
// finished answer is only ever its starter's, however late the starter asks,
// and is dropped when another sequence asks.
func pollPrepareHotspot(token string) (done bool, result int32) {
	prepareFlight.mu.Lock()
	defer prepareFlight.mu.Unlock()
	if prepareFlight.finished && prepareFlight.token == token {
		prepareFlight.finished = false
		return true, prepareFlight.result
	}
	if prepareFlight.running {
		return false, 0
	}
	prepareFlight.token, prepareFlight.running, prepareFlight.finished = token, true, false
	go func() {
		result := prepareHotspotOnce()
		prepareFlight.mu.Lock()
		prepareFlight.result, prepareFlight.finished, prepareFlight.running = result, true, false
		prepareFlight.mu.Unlock()
	}()
	return false, 0
}

// hotspotRunning says that a Mobile hotspot's adapter is up. Restarting
// SharedAccess then turns the hotspot off.
func hotspotRunning(os hotspotOS) bool {
	up, err := os.HotspotAdapters()
	// An adapter list that cannot be read is no proof that none runs.
	return len(up) > 0 || err != nil
}

// HotspotRunning says whether a Mobile hotspot runs on this PC; false off
// Windows. A test that would act on a hotspot checks it first.
func HotspotRunning() bool {
	return hotspotSupported && hotspotRunning(hotspotOSFactory())
}

var errHotspotStarted = errors.New("a hotspot started while ICS was being repaired")

// restartUnlessHotspotRuns is the last look before ICS is restarted: a hotspot
// that started since the repair began is left alone.
func restartUnlessHotspotRuns(os hotspotOS, restart func() error) error {
	if hotspotRunning(os) {
		return errHotspotStarted
	}
	return restart()
}

// SetHotspotSharing takes the whole wanted state of the hotspot's sharing, as
// the JSON of hotspotSharingRequest.
func SetHotspotSharing(requestJSON string) int32 {
	if !hotspotSupported {
		return hotspotResultUnsupported
	}
	if globalController == nil {
		return ResultError
	}
	var request hotspotSharingRequest
	if err := json.Unmarshal([]byte(requestJSON), &request); err != nil {
		return hotspotResultBadRequest
	}
	if _, err := parseBlockedClients(request.BlockedClients); err != nil {
		return hotspotResultBadRequest
	}
	if useServiceIPC {
		code, err := serviceSetHotspotSharing(requestJSON)
		if err != nil {
			logfmt.Warnf("[hotspot] service set sharing failed: %v", err)
			return ResultError
		}
		return code
	}
	return runFFICall(func() int32 { return globalController.setHotspotSharing(request) })
}

// hotspotOSFactory makes the operating-system side of a hotspot order; a test
// replaces it with a fake.
var hotspotOSFactory = newHotspotOS

func (x *CoreController) setHotspotSharing(request hotspotSharingRequest) int32 {
	sharing := x.hotspot.Load()
	if sharing == nil {
		currentPhase := func() tunnelPhase { return tunnelPhase(x.enginePhase.Load()) }
		fresh := newHotspotSharing(hotspotOSFactory(), func(payload string) {
			x.emitStatus(HotspotSharingEvent, payload)
		}, currentPhase())
		fresh.proxySession = x.proxySession.Load
		fresh.useWorker(hotspotReconcileEvery)
		if x.hotspot.CompareAndSwap(nil, fresh) {
			// Events between reading the phase and publishing the order missed it.
			fresh.adoptPhase(currentPhase)
			sharing = fresh
		} else {
			sharing = x.hotspot.Load()
		}
	}
	if err := sharing.set(request); err != nil {
		return hotspotResultBadRequest
	}
	return ResultSuccess
}

// replayHotspot gives a client that attaches later what the hotspot's sharing
// last did.
func (x *CoreController) replayHotspot() {
	if sharing := x.hotspot.Load(); sharing != nil {
		if payload := sharing.lastPublished(); payload != "" {
			x.emitStatus(HotspotSharingEvent, payload)
		}
	}
}
