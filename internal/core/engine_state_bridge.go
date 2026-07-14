//go:build !no_xray || (!no_mihomo && !no_awg)

package core

import "github.com/xjasonlyu/tun2socks/v2/engine"

type bridgeState struct {
	tun2socksKey *engine.Key
}
