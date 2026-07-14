//go:build !no_awg

package core

import "testing"

func TestEngineRegistry_HasAwg(t *testing.T) {
	e, ok := engineRegistry["awg"]
	if !ok {
		t.Fatal(`engine "awg" not registered`)
	}
	if e.ID() != "awg" {
		t.Errorf(`engine "awg" reports ID() = %q`, e.ID())
	}
}
