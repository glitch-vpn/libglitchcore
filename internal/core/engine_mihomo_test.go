//go:build !no_mihomo

package core

import (
	"testing"
	"time"

	mihomoCfg "github.com/metacubex/mihomo/config"
	mihomoLog "github.com/metacubex/mihomo/log"
)

func TestEngineRegistry_HasMihomo(t *testing.T) {
	e, ok := engineRegistry["mihomo"]
	if !ok {
		t.Fatal(`engine "mihomo" not registered`)
	}
	if e.ID() != "mihomo" {
		t.Errorf(`engine "mihomo" reports ID() = %q`, e.ID())
	}
}

// mihomo's events reach the sink at mihomo's own level, through its
// subscription, while its stdout printer stays off.
func TestMihomoLogBridge_KeepsMihomosLevel(t *testing.T) {
	logs := captureLogs(t, 2)
	silenceMihomoPrinter()
	startMihomoLogBridge()
	t.Cleanup(stopMihomoLogBridge)

	mihomoLog.Debugln("[DNS] resolve %s", "example.com")
	mihomoLog.Infoln("[TCP] dial failed")
	mihomoLog.Warnln("[Provider] error in health check")
	mihomoLog.Errorln("[Config] started")

	want := []capturedLog{
		{LogEvent, "debug", "mihomo", "[DNS] resolve example.com"},
		{LogEvent, "info", "mihomo", "[TCP] dial failed"},
		{LogEvent, "warn", "mihomo", "[Provider] error in health check"},
		{LogError, "error", "mihomo", "[Config] started"},
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(logs()) < len(want) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	assertLogs(t, logs(), want)
	if mihomoLog.Level() != mihomoLog.SILENT {
		t.Errorf("mihomo's own printer is at %v, want silent", mihomoLog.Level())
	}
}

// ApplyConfig sets mihomo's printer from the config it is given.
func TestMihomoTeardownConfig_IsSilent(t *testing.T) {
	cfg, err := mihomoCfg.Parse([]byte(mihomoTeardownConfig))
	if err != nil {
		t.Fatalf("teardown config does not parse: %v", err)
	}
	if cfg.General.LogLevel != mihomoLog.SILENT {
		t.Fatalf("teardown config level = %v, want silent", cfg.General.LogLevel)
	}
}
