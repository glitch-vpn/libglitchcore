//go:build integration

package smoke

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// writeGeoFixtures materializes minimal geosite.dat/geoip.dat (v2fly wire
// format, shared by xray and mihomo) carrying a GLITCH-TEST list. A CN list
// rides along because mihomo verifies geo files by loading "CN" and replaces
// a file that lacks it with a downloaded one.
func writeGeoFixtures(t *testing.T, dir string) {
	t.Helper()
	site, err := proto.Marshal(&geodata.GeoSiteList{Entry: []*geodata.GeoSite{
		{
			Code: "GLITCH-TEST",
			Domain: []*geodata.Domain{
				{Type: geodata.Domain_Domain, Value: "glitch.test"},
				{Type: geodata.Domain_Full, Value: "exact.glitch.test"},
			},
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

// A geo rule hard-fails cfg.Build() when the .dat files are unresolvable, so
// EngineConnected is itself the assertion that geoAssetsDir took effect - the
// test binary's exe dir (the env default) carries no .dat files.
func TestSmoke_GeoAssetsDirOpt_Xray(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	dir := t.TempDir()
	writeGeoFixtures(t, dir)

	upstream := startVlessServer(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Geo", testUUID, upstream)
	startProxyEngine(t, link, map[string]string{
		"geoAssetsDir": dir,
		"routingTiers": `[{"direct":["geosite:glitch-test","geoip:glitch-test"]}]`,
		"disableIPv6":  "1",
	})
	ev.waitFor(t, core.EngineConnected, 30*time.Second)
}

// Upstream mihomo bootstraps a missing .dat by downloading it; the caller owns
// those files, so the start must fail instead - and without touching the
// network (the test dir stays empty afterwards).
func TestSmoke_GeoAssetsMissing_MihomoFailsInsteadOfDownloading(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	dir, err := os.MkdirTemp("", "glitch-geo-empty-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	upstream := startVlessServer(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#NoGeo", testUUID, upstream)
	core.EngineStart("mihomo", core.EngineStartRequest{
		Config: link,
		DNS:    "1.1.1.1",
		Opts: map[string]string{
			"proxyPort":    strconv.Itoa(freePort(t)),
			"geoAssetsDir": dir,
			"routingTiers": `[{"direct":["geosite:glitch-test"]}]`,
			"disableIPv6":  "1",
		},
	})
	t.Cleanup(func() { stopEngine(t, "mihomo") })

	if msg := ev.waitFor(t, core.EngineError, 20*time.Second); !strings.Contains(msg, "geosite.dat not found") {
		t.Fatalf("EngineError = %q, want a missing-geosite error", msg)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(strings.ToLower(e.Name()), ".dat") {
			t.Fatalf("mihomo downloaded %q into the caller's dir", e.Name())
		}
	}
}

// mihomo loads geo at config parse time and memoizes matchers by list name;
// the second connect with a different dir proves the per-connection re-apply
// (SetHomeDir + matcher cache clear).
func TestSmoke_GeoAssetsDirOpt_Mihomo(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upstream := startVlessServer(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#GeoM", testUUID, upstream)

	for i := 0; i < 2; i++ {
		// Not t.TempDir(): mihomo opens cache.db inside its home dir and can
		// hold it past engine stop, which would fail t.TempDir's strict cleanup
		// on Windows. Best-effort removal instead.
		dir, err := os.MkdirTemp("", "glitch-geo-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		writeGeoFixtures(t, dir)

		res := core.EngineStart("mihomo", core.EngineStartRequest{
			Config: link,
			DNS:    "1.1.1.1",
			Opts: map[string]string{
				"proxyPort":    strconv.Itoa(freePort(t)),
				"geoAssetsDir": dir,
				"routingTiers": `[{"direct":["geosite:glitch-test","geoip:glitch-test"]}]`,
				"disableIPv6":  "1",
			},
		})
		if res != core.ResultSuccess {
			t.Fatalf("EngineStart mihomo (round %d) = %d", i+1, res)
		}
		ev.waitFor(t, core.EngineConnected, 30*time.Second)

		stopEngine(t, "mihomo")
		ev.reset()
	}
}
