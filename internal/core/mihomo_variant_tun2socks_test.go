//go:build !no_mihomo && !no_xray && with_tun2socks

package core

import (
	"runtime"
	"testing"
)

// With the with_tun2socks tag Windows takes the bridge for mihomo, as xray
// does, and Android only on request; a proxy-mode session never has a TUN.
func TestMihomoUsesTheBridgeWithTheTun2socksTag(t *testing.T) {
	t.Setenv("GLITCH_MIHOMO_ANDROID_BRIDGE", "")
	x := &CoreController{}
	if got, want := x.mihomoUsesBridge(0), runtime.GOOS == "windows"; got != want {
		t.Fatalf("%s: bridge %v, want %v", runtime.GOOS, got, want)
	}
	if x.mihomoUsesBridge(7890) {
		t.Fatal("a proxy-mode session takes the bridge")
	}
}
