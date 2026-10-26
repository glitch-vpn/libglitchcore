package core

import (
	"testing"
	"time"
)

// A start or a stop holds coreMutex for its whole run, minutes when a stop
// hangs; the Android notification reads traffic every second through JNI.
func readTrafficWhileTheCoreIsHeld(t *testing.T, x *CoreController) (rx, tx uint64, running bool) {
	t.Helper()
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()
	type reading struct {
		rx, tx  uint64
		running bool
	}
	read := make(chan reading, 1)
	go func() {
		rx, tx, running := x.readEngineTraffic()
		read <- reading{rx, tx, running}
	}()
	select {
	case r := <-read:
		return r.rx, r.tx, r.running
	case <-time.After(2 * time.Second):
		t.Fatal("traffic read waited on coreMutex")
		return 0, 0, false
	}
}
