//go:build service && windows && integration && !no_xray && !no_mihomo

package core

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"

	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
)

// The service build never talks to a real pipe here: dispatchCommand is called
// directly, and useServiceIPC is false, so engine_start runs the engine in
// this process - exactly what the installed service does.
//
//	go test -tags="service integration with_gvisor" ./internal/core/ -run TestServiceDispatch
//
// A start over dispatch with geo rules runs on the caller's geo files, read
// from the service's own folder, and writes nothing into the caller's.
func TestServiceDispatch_EngineStart_GeoAssetsDir(t *testing.T) {
	for _, engine := range []string{"xray", "mihomo"} {
		t.Run(engine, func(t *testing.T) {
			home := testServiceHome(t)
			callerDir := t.TempDir()
			writeServiceGeoFixtures(t, callerDir)
			startOverDispatch(t, engine, callerDir)

			// The caller's folder is read only: whatever the engine writes
			// (mihomo's cache.db) lands in the service's own folder.
			entries, err := os.ReadDir(callerDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != len(geoAssetFileNames) {
				t.Fatalf("the caller's folder gained a file: %v", entries)
			}
			// mihomo opens cache.db once per process, in whatever home the
			// first start had, so only the home itself is checked here.
			if engine == "mihomo" {
				if rel, err := filepath.Rel(home.root, mihomoHomeDir); err != nil || !filepath.IsLocal(rel) {
					t.Fatalf("mihomo's home %q is outside the service's folder %q", mihomoHomeDir, home.root)
				}
			}
		})
	}
}

// startOverDispatch sends an engine_start through the service's dispatch and
// waits for the engine to connect; the stop runs at cleanup.
func startOverDispatch(t *testing.T, engine, callerDir string) {
	t.Helper()
	Initialize()

	var mu sync.Mutex
	byCode := map[int32][]string{}
	setStatusSink(func(code int32, msg string) {
		mu.Lock()
		byCode[code] = append(byCode[code], msg)
		mu.Unlock()
		t.Logf("event %d: %s", code, msg)
	})
	t.Cleanup(func() { setStatusSink(nil) })

	t.Setenv("GLITCH_SOCKS_READY_TIMEOUT_SEC", "20")
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	proxyPort, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	req, err := json.Marshal(EngineStartRequest{
		Config: fmt.Sprintf("vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:%d?security=none&type=tcp#SvcGeo", port),
		DNS:    "1.1.1.1",
		Opts: map[string]string{
			"proxyPort":    fmt.Sprint(proxyPort),
			"proxyUser":    "svc",
			"proxyPass":    "secret",
			"geoAssetsDir": callerDir,
			"routingTiers": `[{"direct":["geosite:glitch-test","geoip:glitch-test"]}]`,
			"disableIPv6":  "1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"engineId": engine, "request": string(req)})

	resp := dispatchCommand(pipeCommand{Action: "engine_start", Payload: payload})
	if !resp.OK {
		t.Fatalf("engine_start over dispatch failed: %s", resp.Error)
	}
	t.Cleanup(func() {
		stopPayload, _ := json.Marshal(map[string]string{"engineId": engine})
		dispatchCommand(pipeCommand{Action: "engine_stop", Payload: stopPayload})
		deadline := time.Now().Add(10 * time.Second)
		for globalController.engineIsRunning(engine) == glitchCoreResultSuccess && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
		}
		// The teardown goroutine keeps logging after the running flag drops,
		// and the status sink is package-global: without settling here those lines land
		// in the next test's sink and break its event count.
		time.Sleep(500 * time.Millisecond)
	})

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		connected := len(byCode[EngineConnected]) > 0
		failed := byCode[EngineError]
		mu.Unlock()
		if connected {
			return
		}
		if len(failed) > 0 {
			t.Fatalf("EngineError instead of EngineConnected: %v", failed)
		}
		time.Sleep(100 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("no EngineConnected within 30s; captured: %v", byCode)
}

// A CN list rides along because mihomo verifies geo files by loading "CN".
// Forked from the smoke suite's writeGeoFixtures: smoke imports core, and a
// shared home would need its own no_xray tagging ceremony for two callers.
func writeServiceGeoFixtures(t *testing.T, dir string) {
	t.Helper()
	site, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{
			Code:   "GLITCH-TEST",
			Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "glitch.test"}},
		},
		{
			Code:   "CN",
			Domain: []*geodata.Domain{{Type: geodata.Domain_Domain, Value: "cn.glitch.test"}},
		},
	}})
	if err != nil {
		t.Fatalf("geosite fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geosite.dat"), site, 0o644); err != nil {
		t.Fatal(err)
	}
	ip, err := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{
			Code: "GLITCH-TEST",
			Cidr: []*geodata.CIDR{{Ip: net.ParseIP("198.51.100.0").To4(), Prefix: 24}},
		},
		{
			Code: "CN",
			Cidr: []*geodata.CIDR{{Ip: net.ParseIP("203.0.113.0").To4(), Prefix: 24}},
		},
	}})
	if err != nil {
		t.Fatalf("geoip fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat"), ip, 0o644); err != nil {
		t.Fatal(err)
	}
}
