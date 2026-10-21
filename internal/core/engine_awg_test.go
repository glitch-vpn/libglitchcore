//go:build !no_awg

package core

import (
	"strings"
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

// engineStart keeps every proxyPort start in-process, so the refusal has to
// happen here or a TUN comes up in the caller's process.
func TestHandleAwgStart_RefusesProxyMode(t *testing.T) {
	var codes []int32
	var messages []string
	setStatusSink(func(code int32, message string) {
		codes = append(codes, code)
		messages = append(messages, message)
	})
	defer setStatusSink(nil)

	ctl := &CoreController{nextHandle: 1}
	got := ctl.HandleAwgStart(EngineStartRequest{
		Config: "awg://unused",
		Opts:   map[string]string{"proxyPort": "10808"},
	})

	if got != glitchCoreResultError {
		t.Fatalf("result = %d, want error", got)
	}
	if len(codes) != 1 || codes[0] != EngineError || !strings.Contains(messages[0], "proxyPort") {
		t.Fatalf("events = %v %q, want one EngineError naming proxyPort", codes, messages)
	}
	if ctl.isAwgRunning.Load() {
		t.Fatal("awg marked running after a refused proxy-mode start")
	}
}

func TestHandleAwgStart_RefusesRawConfigInPool(t *testing.T) {
	var codes []int32
	setStatusSink(func(code int32, _ string) { codes = append(codes, code) })
	defer setStatusSink(nil)

	ctl := &CoreController{nextHandle: 1}
	got := ctl.HandleAwgStart(EngineStartRequest{Config: rawINIConfig + "\nawg://AAAA#two"})

	if got != glitchCoreResultError || len(codes) != 1 || codes[0] != EngineError {
		t.Fatalf("result = %d, events = %v; want error and one EngineError", got, codes)
	}
}
