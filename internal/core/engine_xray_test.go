//go:build !no_xray

package core

import "testing"

func TestEngineRegistry_HasXray(t *testing.T) {
	e, ok := engineRegistry["xray"]
	if !ok {
		t.Fatal(`engine "xray" not registered`)
	}
	if e.ID() != "xray" {
		t.Errorf(`engine "xray" reports ID() = %q`, e.ID())
	}
}
