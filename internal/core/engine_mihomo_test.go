//go:build !no_mihomo

package core

import (
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/conninspect"
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

func TestMihomoRejectRecord_ReadsTheRuleMatchLine(t *testing.T) {
	cases := []struct {
		line string
		ok   bool
		want conninspect.Record
	}{
		{
			line: "[TCP] 127.0.0.1:51245 --> blocked.test:80 match DomainSuffix(blocked.test) using REJECT",
			ok:   true,
			want: conninspect.Record{Engine: "mihomo", Src: "127.0.0.1:51245", Status: "rejected", Network: "tcp",
				Host: "blocked.test", Port: "80", Outbound: "REJECT", Rule: "DomainSuffix blocked.test"},
		},
		{
			line: "[UDP] 10.0.0.2:5353(app.exe, uid=10123) --> [2001:db8::1]:443 match AND((NETWORK,udp),(NOT,((DST-PORT,53)))) using REJECT-DROP",
			ok:   true,
			want: conninspect.Record{Engine: "mihomo", Src: "10.0.0.2:5353", Status: "rejected", Network: "udp",
				Host: "2001:db8::1", Port: "443", Outbound: "REJECT-DROP", Rule: "AND (NETWORK,udp),(NOT,((DST-PORT,53)))"},
		},
		{line: "[TCP] 127.0.0.1:51247 --> a.test:443 match Match using x[REJECT]", ok: false},
		{line: "[TCP] 127.0.0.1:51247 --> 127.0.0.1:51246 match Match using Inspect", ok: false},
		{line: "[TCP] dial Inspect (match Match/) 127.0.0.1:1 --> a.test:443 error: refused", ok: false},
	}
	for _, c := range cases {
		got, ok := mihomoRejectRecord(c.line)
		if ok != c.ok || got != c.want {
			t.Errorf("mihomoRejectRecord(%q) = %+v, %v; want %+v, %v", c.line, got, ok, c.want, c.ok)
		}
	}
}

func TestHandleMihomoStart_RefusesRawConfigInPool(t *testing.T) {
	var codes []int32
	setStatusSink(func(code int32, _ string) { codes = append(codes, code) })
	defer setStatusSink(nil)

	ctl := &CoreController{nextHandle: 1}
	got := ctl.HandleMihomoStart(EngineStartRequest{Config: rawINIConfig + "\nhysteria2://p@h:443"})

	if got != glitchCoreResultError || len(codes) != 1 || codes[0] != EngineError {
		t.Fatalf("result = %d, events = %v; want error and one EngineError", got, codes)
	}
}
