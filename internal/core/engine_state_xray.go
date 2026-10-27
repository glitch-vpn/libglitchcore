//go:build !no_xray

package core

import (
	"sync/atomic"

	xrayCore "github.com/xtls/xray-core/core"
	xrayStats "github.com/xtls/xray-core/features/stats"
)

type xrayState struct {
	xrayCoreInstance *xrayCore.Instance
	// From the start's request until its goroutine ends: the engine counts as
	// running, so a stop in that time is taken rather than refused.
	xrayStarting atomic.Bool
	// Read without coreMutex, which a start or a stop holds for its whole run;
	// the manager's counters are atomics.
	xrayTraffic atomic.Pointer[xrayTrafficSource]
}

// xrayTrafficSource is one session's counters: its proxy outbounds' tags, the
// traffic summed over them.
type xrayTrafficSource struct {
	stats xrayStats.Manager
	tags  []string
}
