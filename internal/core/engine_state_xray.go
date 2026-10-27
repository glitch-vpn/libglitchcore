//go:build !no_xray

package core

import (
	"context"
	"sync/atomic"

	xrayCore "github.com/xtls/xray-core/core"
	xrayStats "github.com/xtls/xray-core/features/stats"
)

type xrayState struct {
	xrayCoreInstance *xrayCore.Instance
	// The instance's own context: xray ends every connection it accepted or
	// was handed when it is cancelled, which closing the instance does not do.
	xrayLife       context.Context
	xrayLifeCancel context.CancelFunc
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
