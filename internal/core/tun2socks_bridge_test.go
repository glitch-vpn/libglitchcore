//go:build !no_xray || (!no_mihomo && !no_awg)

package core

import (
	"os"
	"runtime"
	"testing"
)

// An engine that cannot start comes back as the start's error; tun2socks
// ends the whole process on one it reports itself.
func TestStartTun2socksReportsStartFailure(t *testing.T) {
	tunFd := 0
	if runtime.GOOS != "windows" {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		defer r.Close()
		defer w.Close()
		tunFd = int(r.Fd())
	}

	x := &CoreController{}
	err := x.startTun2socks(tun2socksParams{tunFd: tunFd, logLevel: "no-such-level"})
	if err == nil {
		x.stopTun2socks()
		t.Fatal("startTun2socks with an invalid log level returned nil")
	}
	if x.isTun2socksRunning.Load() || x.tun2socksKey != nil {
		t.Error("a failed start left the bridge marked as running")
	}
}

func TestStopTun2socksBeforeStartIsNoOp(t *testing.T) {
	x := &CoreController{}
	x.stopTun2socks()
	if x.isTun2socksRunning.Load() {
		t.Error("a stop before any start marked the bridge as running")
	}
}
