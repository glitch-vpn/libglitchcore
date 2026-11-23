//go:build !no_mihomo

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

// The mihomo twin of TestXrayStart_ArmsTheIPEchoBeforeLivenessCanCallTheLinkUp:
// a link-up that liveness reports before the echo is armed is dropped, and the
// session never gets an IPEvent. The start is held at the first lock the server
// state and the arming take, so it fails when liveness starts ahead of both.
func TestMihomoStart_ArmsTheIPEchoBeforeLivenessCanCallTheLinkUp(t *testing.T) {
	x := newMihomoSessionController(t)
	events := collectEvents(t, IPEvent)

	var probes atomic.Int32
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(probe.Close)
	echo := echoServer(t, "198.51.100.9")

	request, _ := mihomoProxyStart(t, mihomoSessionHome(t))
	request.Config = "socks://127.0.0.1:" + strconv.Itoa(relayingSocks(t)) + "#exit"
	request.Opts["resolveExternalIp"] = "1"
	request.Opts["probeUrl"] = probe.URL
	request.Opts["ipv4EchoUrl"] = echo.URL
	request.Opts["disableIPv6"] = "1"

	x.ipFetchMu.Lock()
	started := make(chan int32, 1)
	go func() { started <- x.HandleMihomoStart(request) }()
	for deadline := time.Now().Add(3 * time.Second); probes.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	x.ipFetchMu.Unlock()

	if result := <-started; result != glitchCoreResultSuccess {
		t.Fatalf("mihomo start = %d", result)
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
