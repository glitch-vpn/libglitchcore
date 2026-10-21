//go:build !no_awg

package core

import (
	"sync/atomic"
	"testing"
)

func TestEngineRegistry_HasAwg(t *testing.T) {
	e, ok := engineRegistry["awg"]
	if !ok {
		t.Fatal(`engine "awg" not registered`)
	}
	if e.ID() != "awg" {
		t.Errorf(`engine "awg" reports ID() = %q`, e.ID())
	}
}

// The device logger is built once per device; the gate is read per line.
func TestAwgDeviceLogger_LevelsAndLiveGate(t *testing.T) {
	logs := captureLogs(t, 1)
	logger := awgDeviceLogger()

	logger.Verbosef("peer(%s) - Sending handshake initiation", "abcd")
	logger.Errorf("Failed to send handshake initiation: %v", "unreachable")
	atomic.StoreInt32(&statusVerbosity, 2)
	logger.Verbosef("Routine: receive incoming - started")

	want := []capturedLog{
		{LogError, "error", "AWG", "Failed to send handshake initiation: unreachable"},
		{LogEvent, "debug", "AWG", "Routine: receive incoming - started"},
	}
	assertLogs(t, logs(), want)
}

func TestAwgDeviceLogger_HoldsVerboseLinesToABudget(t *testing.T) {
	logs := captureLogs(t, 2)
	logger := awgDeviceLogger()

	for i := 0; i < 500; i++ {
		logger.Verbosef("awg: process packet: %v", "bad header")
	}
	logger.Errorf("Failed to send data packets: %v", "unreachable")

	got := logs()
	if len(got) > 41 {
		t.Fatalf("500 verbose lines let %d through", len(got)-1)
	}
	if last := got[len(got)-1]; last.Level != "error" {
		t.Fatalf("the error line after a flood was held back: %+v", last)
	}
}
