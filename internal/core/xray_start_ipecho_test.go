//go:build !no_xray

package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// A session that has no way to fetch its exit's IP when liveness first calls
// the link up gets no IPEvent at all: the link-up is the only trigger. The
// start is held where it takes the lock the arming takes, so liveness, if it
// has already begun, finishes its first probe before the arming happens.
func TestXrayStart_ArmsTheIPEchoBeforeLivenessCanCallTheLinkUp(t *testing.T) {
	x := &CoreController{}
	t.Cleanup(func() {
		x.stopStats()
		x.coreMutex.Lock()
		defer x.coreMutex.Unlock()
		x.endSessionLoops()
		x.xrayStopLocked()
	})
	events := collectEvents(t, IPEvent)

	var probes atomic.Int32
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(probe.Close)
	echo := echoServer(t, "198.51.100.9")

	request, _ := xrayProxyStart(t)
	request.Config = "socks://127.0.0.1:" + strconv.Itoa(relayingSocks(t)) + "#exit"
	request.Opts["resolveExternalIp"] = "1"
	request.Opts["probeUrl"] = probe.URL
	request.Opts["ipv4EchoUrl"] = echo.URL
	request.Opts["disableIPv6"] = "1"

	x.ipFetchMu.Lock()
	started := make(chan int32, 1)
	go func() { started <- x.HandleXrayStart(request) }()
	for deadline := time.Now().Add(time.Second); probes.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	x.ipFetchMu.Unlock()

	if result := <-started; result != glitchCoreResultSuccess {
		t.Fatalf("xray start = %d", result)
	}
	waitFor(t, "the IPEvent", func() bool { return len(events()) > 0 })
	var state externalIPState
	if err := json.Unmarshal([]byte(events()[0]), &state); err != nil {
		t.Fatal(err)
	}
	if state.IPv4 != "198.51.100.9" {
		t.Fatalf("IPEvent = %+v, want the echo's address", state)
	}
}
