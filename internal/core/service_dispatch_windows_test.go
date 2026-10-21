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
