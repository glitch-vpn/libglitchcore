//go:build !no_xray

package core

import (
	xrayCore "github.com/xtls/xray-core/core"
	xrayStats "github.com/xtls/xray-core/features/stats"
)

type xrayState struct {
	xrayStatsManager xrayStats.Manager
	xrayCoreInstance *xrayCore.Instance
}
