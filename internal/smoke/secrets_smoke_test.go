//go:build integration

package smoke

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// Made-up credentials in the formats real links carry them; the lines this
// test recorded are internal/logfmt/testdata/engine_lines.txt, whose test
// lists them too.
const (
	smokeRealityKey = "Qzm3mXq2Gk5n0yR7vT1cF8hJ4pL6sW9aBxDeNuIoKtE"
	smokeShortID    = "6ba85179e30d4fc2"
	smokeTrojanPass = "Tr0janSmokePass"
	smokeHy2Pass    = "Hy2SmokePass"
	smokeObfsPass   = "ObfsSmokePass"
)

// Every engine runs at full verbosity through the paths that put a link's
// credentials into text - a link the parser rejects, a dial that fails - and no
// event payload may carry one.
func TestSmoke_NoSecretLeavesInEvents(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)
	core.ApplyStatusVerbosity(2)
	t.Cleanup(func() { core.ApplyStatusVerbosity(-1) })
	t.Setenv("GLITCH_SOCKS_READY_TIMEOUT_SEC", "20")

	upstream := startVlessServer(t)
	echo := echoBody(t, "198.51.100.43")
	echoURL, _ := url.Parse(echo.URL)
	echoPort, _ := strconv.Atoi(echoURL.Port())

	good := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Good", testUUID, upstream)
	proxyPort := startProxyEngineDNS(t, good, map[string]string{
		"probeUrl":          echo.URL,
		"resolveExternalIp": "0",
	}, nil)
	ev.waitFor(t, core.EngineConnected, 30*time.Second)
	if _, err := socksConnect(proxyPort, "127.0.0.1", uint16(echoPort)); err != nil {
		t.Logf("socks through xray: %v", err)
	}
	stopEngine(t, "xray")
	ev.waitFor(t, core.EngineDisconnected, 15*time.Second)

	rejected := fmt.Sprintf("vless://%s@127.0.0.1:notaport?security=reality&pbk=%s&sid=%s&type=tcp#Bad",
		testUUID, smokeRealityKey, smokeShortID)
	startExpectingError(t, ev, "xray", rejected)

	dead := freePort(t)
	trojan := fmt.Sprintf("trojan://%s@127.0.0.1:%d?security=none&type=tcp#Dead", smokeTrojanPass, dead)
	seenConnected := len(ev.all(core.EngineConnected))
	mixedPort := startEngineInProxyMode(t, "mihomo", trojan, map[string]string{
		"resolveExternalIp": "0",
	}, nil)
	if !ev.waitForNew(t, core.EngineConnected, seenConnected, 30*time.Second) {
		lastError, _ := ev.last(core.EngineError)
		t.Fatalf("mihomo did not reach EngineConnected: %s", lastError)
	}
	if _, err := socksConnect(mixedPort, "127.0.0.1", uint16(echoPort)); err == nil {
		t.Log("socks through a dead trojan upstream unexpectedly answered")
	}
	if ev.waitForLog(t, func(msg string) bool { return strings.Contains(msg, "127.0.0.1:"+strconv.Itoa(dead)) }, 5*time.Second) == "" {
		t.Fatal("mihomo never logged the failed dial to the trojan upstream")
	}
	stopEngine(t, "mihomo")

	hy2 := fmt.Sprintf("hysteria2://%s@127.0.0.1:notaport?obfs=salamander&obfs-password=%s#BadHy2", smokeHy2Pass, smokeObfsPass)
	startExpectingError(t, ev, "mihomo", hy2)

	secrets := []string{testUUID, smokeRealityKey, smokeShortID, smokeTrojanPass, smokeHy2Pass, smokeObfsPass}
	events := ev.everything()
	lines := 0
	for code, msgs := range events {
		for _, msg := range msgs {
			lines++
			for _, secret := range secrets {
				if strings.Contains(msg, secret) {
					t.Errorf("event %d carries %q: %s", code, secret, msg)
				}
			}
		}
	}
	if len(events[core.LogEvent]) == 0 || len(events[core.EngineError]) < 2 {
		t.Fatalf("the run produced too little to check: %d events, %d log lines, %d errors",
			lines, len(events[core.LogEvent]), len(events[core.EngineError]))
	}
}

func startExpectingError(t *testing.T, ev *eventLog, engine, link string) {
	t.Helper()
	before := len(ev.all(core.EngineError))
	res := core.EngineStart(engine, core.EngineStartRequest{
		Config: link,
		DNS:    "1.1.1.1",
		Opts:   map[string]string{"proxyPort": strconv.Itoa(freePort(t))},
	})
	if res != core.ResultSuccess {
		return
	}
	if !ev.waitForNew(t, core.EngineError, before, 15*time.Second) {
		stopEngine(t, engine)
		t.Fatalf("%s accepted a link it cannot parse", engine)
	}
}
