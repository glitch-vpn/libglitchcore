//go:build service && windows && integration

package core

import (
	"encoding/json"
	"testing"
	"time"
)

func TestServiceDispatch_SetConnInspector(t *testing.T) {
	Initialize()
	prev := connInspectEnabled.Load()
	t.Cleanup(func() { connInspectEnabled.Store(prev) })

	for _, enabled := range []bool{true, false} {
		payload, _ := json.Marshal(map[string]bool{"enabled": enabled})
		if resp := dispatchCommand(pipeCommand{Action: "set_conn_inspector", Payload: payload}); !resp.OK {
			t.Fatalf("set_conn_inspector %v: %s", enabled, resp.Error)
		}
		if got := connInspectEnabled.Load(); got != enabled {
			t.Fatalf("after set_conn_inspector %v the inspector is %v", enabled, got)
		}
	}
}

// Off with nothing ever turned on is a request the service answers with the
// result code in data, and then applies off its command: the worker's answer is
// the event. The operating system behind it is a fake, so a run of this test
// with administrator rights never stops a hotspot that runs on the machine.
func TestServiceDispatch_SetHotspotSharingOff(t *testing.T) {
	Initialize()
	os := useFakeHotspotOS(t, globalController)
	events := captureHotspotEvents(t)

	payload, _ := json.Marshal(map[string]string{"request": `{"on":false,"blockWhileTunnelDown":true,"blockedClients":[]}`})
	resp := dispatchCommand(pipeCommand{Action: "set_hotspot_sharing", Payload: payload})
	if !resp.OK {
		t.Fatalf("set_hotspot_sharing: %s", resp.Error)
	}
	if data, _ := resp.Data.(map[string]int32); data["result"] != ResultSuccess {
		t.Fatalf("result = %v, want %d", resp.Data, ResultSuccess)
	}
	events.wait(hotspotSharingEvent{Shared: hotspotSharedNone})
	if os.callsMatching("unshare") != 0 || os.callsMatching("forwarding") != 0 {
		t.Errorf("off touched the user's own hotspot: %v", os.calls)
	}

	bad, _ := json.Marshal(map[string]string{"request": `{`})
	if resp := dispatchCommand(pipeCommand{Action: "set_hotspot_sharing", Payload: bad}); resp.OK {
		t.Error("a request that is not JSON was accepted")
	}
}

// prepare_hotspot starts the repair off the command and answers at once; the
// client asks again with its token until the repair is done, and the answer is
// only its own.
func TestServiceDispatch_PrepareHotspotRunsOffTheCommand(t *testing.T) {
	release, runs := replacePrepare(t, hotspotResultRunning)
	ask := func(token string) (done bool, result int32, ok bool) {
		payload, _ := json.Marshal(map[string]string{"token": token})
		resp := dispatchCommand(pipeCommand{Action: "prepare_hotspot", Payload: payload})
		data, _ := resp.Data.(map[string]any)
		done, _ = data["done"].(bool)
		result, _ = data["result"].(int32)
		return done, result, resp.OK
	}

	started := time.Now()
	if done, _, ok := ask("a"); !ok || done {
		t.Fatalf("a repair under way answered done %t, ok %t", done, ok)
	}
	if time.Since(started) > 2*time.Second {
		t.Error("the command waited for the repair")
	}
	if done, _, _ := ask("b"); done {
		t.Error("another caller was answered while the repair runs")
	}
	release()
	deadline := time.After(5 * time.Second)
	for {
		if done, result, _ := ask("a"); done {
			if result != hotspotResultRunning {
				t.Errorf("result = %d, want %d", result, hotspotResultRunning)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("the repair never finished")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if got := runs(); got != 1 {
		t.Errorf("the repair ran %d times for one caller and a waiting one", got)
	}

	if resp := dispatchCommand(pipeCommand{Action: "prepare_hotspot"}); resp.OK {
		t.Error("a request with no token was accepted")
	}
}
