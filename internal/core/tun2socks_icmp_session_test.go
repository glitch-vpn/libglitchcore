//go:build !no_xray

package core

import (
	_ "unsafe"

	"testing"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/engine"
)

// engineICMPHandler is the handler the next engine start builds its stack with.
//
//go:linkname engineICMPHandler github.com/xjasonlyu/tun2socks/v2/engine._icmpHandler
var engineICMPHandler adapter.NetworkHandler

// tun2socks clears its ICMP handler on every stop and on a failed start, so a
// handler set once at init answers the second session's echoes again.
func TestPrepareBridgeEngine_DropsEchoesInEverySession(t *testing.T) {
	for session := 1; session <= 2; session++ {
		prepareBridgeEngine(&engine.Key{})
		if _, ok := engineICMPHandler.(echoRequestDropper); !ok {
			t.Fatalf("session %d: ICMP handler = %T, want the echo dropper", session, engineICMPHandler)
		}
		if err := engine.Stop(); err != nil {
			t.Fatal(err)
		}
	}
}
