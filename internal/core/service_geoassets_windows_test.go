//go:build service && windows && integration && !no_xray

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

	"github.com/xtls/xray-core/app/router"
	"google.golang.org/protobuf/proto"

	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
)

// The service build never talks to a real pipe here: dispatchCommand is called
// directly, and useServiceIPC is false, so engine_start runs the engine in
// this process - exactly what the installed service does.
//
//	go test -tags="service integration with_gvisor" ./internal/core/ -run TestServiceDispatch
//
// Before geoAssetsDir existed this test failed: the request carried no asset
// location, the env pointed at the test binary's dir (no .dat files), and the
// geo rules hard-failed cfg.Build() into EngineError.
func TestServiceDispatch_EngineStart_GeoAssetsDir(t *testing.T) {
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

	dir := t.TempDir()
	writeServiceGeoFixtures(t, dir)

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
			"geoAssetsDir": dir,
			"routingTiers": `[{"direct":["geosite:glitch-test","geoip:glitch-test"]}]`,
			"disableIPv6":  "1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"engineId": "xray", "request": string(req)})

	resp := dispatchCommand(pipeCommand{Action: "engine_start", Payload: payload})
	if !resp.OK {
		t.Fatalf("engine_start over dispatch failed: %s", resp.Error)
	}
	t.Cleanup(func() {
		stopPayload, _ := json.Marshal(map[string]string{"engineId": "xray"})
		dispatchCommand(pipeCommand{Action: "engine_stop", Payload: stopPayload})
		deadline := time.Now().Add(10 * time.Second)
		for globalController.engineIsRunning("xray") == glitchCoreResultSuccess && time.Now().Before(deadline) {
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
	site, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{
		{
			CountryCode: "GLITCH-TEST",
			Domain:      []*router.Domain{{Type: router.Domain_Domain, Value: "glitch.test"}},
		},
		{
			CountryCode: "CN",
			Domain:      []*router.Domain{{Type: router.Domain_Domain, Value: "cn.glitch.test"}},
		},
	}})
	if err != nil {
		t.Fatalf("geosite fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geosite.dat"), site, 0o644); err != nil {
		t.Fatal(err)
	}
	ip, err := proto.Marshal(&router.GeoIPList{Entry: []*router.GeoIP{
		{
			CountryCode: "GLITCH-TEST",
			Cidr:        []*router.CIDR{{Ip: net.ParseIP("198.51.100.0").To4(), Prefix: 24}},
		},
		{
			CountryCode: "CN",
			Cidr:        []*router.CIDR{{Ip: net.ParseIP("203.0.113.0").To4(), Prefix: 24}},
		},
	}})
	if err != nil {
		t.Fatalf("geoip fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat"), ip, 0o644); err != nil {
		t.Fatal(err)
	}
}
