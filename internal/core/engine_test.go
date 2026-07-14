package core

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestEngineDispatch_UnknownEngineRejected(t *testing.T) {
	ctl := &CoreController{}
	ctl.initEngineState()

	if got := ctl.engineStart("nope", EngineStartRequest{}); got != glitchCoreResultError {
		t.Errorf("engineStart(unknown) = %d, want error %d", got, glitchCoreResultError)
	}
	if got := ctl.engineStop("nope"); got != glitchCoreResultError {
		t.Errorf("engineStop(unknown) = %d, want error %d", got, glitchCoreResultError)
	}
	if got := ctl.engineIsRunning("nope"); got != glitchCoreResultError {
		t.Errorf("engineIsRunning(unknown) = %d, want error %d", got, glitchCoreResultError)
	}
}

func TestCoreCapabilities_JSONShape(t *testing.T) {
	var caps struct {
		Engines  []string          `json:"engines"`
		Versions map[string]string `json:"versions"`
	}
	if err := json.Unmarshal([]byte(coreCapabilities()), &caps); err != nil {
		t.Fatalf("coreCapabilities() is not valid JSON: %v", err)
	}
	// Engines are sorted and mirror the registry exactly, whatever this build's
	// composition is (multi: awg/mihomo/xray; solo: mihomo).
	if !slices.IsSorted(caps.Engines) {
		t.Errorf("engines %v not sorted", caps.Engines)
	}
	if len(caps.Engines) != len(engineRegistry) {
		t.Errorf("engines %v, want %d entries (one per registered engine)", caps.Engines, len(engineRegistry))
	}
	for id := range engineRegistry {
		if !slices.Contains(caps.Engines, id) {
			t.Errorf("engines %v missing registered engine %q", caps.Engines, id)
		}
	}
	if caps.Versions == nil {
		t.Error("versions map missing")
	}
}
