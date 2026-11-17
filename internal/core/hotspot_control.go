package core

import (
	"encoding/json"

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
	return prepareHotspot()
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

func (x *CoreController) setHotspotSharing(request hotspotSharingRequest) int32 {
	sharing := x.hotspot.Load()
	if sharing == nil {
		fresh := newHotspotSharing(newHotspotOS(), func(payload string) {
			x.emitStatus(HotspotSharingEvent, payload)
		})
		if x.hotspot.CompareAndSwap(nil, fresh) {
			fresh.start(hotspotReconcileEvery)
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
