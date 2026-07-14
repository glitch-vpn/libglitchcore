//go:build !no_mihomo

package core

import "testing"

func TestEngineRegistry_HasMihomo(t *testing.T) {
	e, ok := engineRegistry["mihomo"]
	if !ok {
		t.Fatal(`engine "mihomo" not registered`)
	}
	if e.ID() != "mihomo" {
		t.Errorf(`engine "mihomo" reports ID() = %q`, e.ID())
	}
}
