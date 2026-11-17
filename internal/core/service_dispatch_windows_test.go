//go:build service && windows && integration

package core

import (
	"encoding/json"
	"testing"
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

// Off with nothing ever turned on is a request the service answers without
// touching a connection, with the result code in data.
func TestServiceDispatch_SetHotspotSharingOff(t *testing.T) {
	Initialize()
	payload, _ := json.Marshal(map[string]string{"request": `{"on":false,"blockWhileTunnelDown":true,"blockedClients":[]}`})
	resp := dispatchCommand(pipeCommand{Action: "set_hotspot_sharing", Payload: payload})
	if !resp.OK {
		t.Fatalf("set_hotspot_sharing: %s", resp.Error)
	}
	if data, _ := resp.Data.(map[string]int32); data["result"] != ResultSuccess {
		t.Fatalf("result = %v, want %d", resp.Data, ResultSuccess)
	}

	bad, _ := json.Marshal(map[string]string{"request": `{`})
	if resp := dispatchCommand(pipeCommand{Action: "set_hotspot_sharing", Payload: bad}); resp.OK {
		t.Error("a request that is not JSON was accepted")
	}
}
