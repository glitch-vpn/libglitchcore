//go:build !no_xray && with_tun2socks

package core

import (
	"sync/atomic"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

// tunLayerState is what the tun2socks bridge holds for a session.
type tunLayerState struct {
	isTun2socksRunning atomic.Bool
	tun2socksKey       *engine.Key
}
