//go:build !no_mihomo && (no_xray || !with_tun2socks)

package core

import "testing"

// Without the with_tun2socks tag mihomo runs on its own TUN on every platform:
// no environment switch hands it to a bridge.
func TestMihomoUsesNoBridgeWithoutTheTun2socksTag(t *testing.T) {
	t.Setenv("GLITCH_MIHOMO_ANDROID_BRIDGE", "1")
	if (&CoreController{}).mihomoUsesBridge(0) {
		t.Fatal("mihomo takes the bridge in a build without it")
	}
}
