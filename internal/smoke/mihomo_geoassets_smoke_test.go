//go:build integration && !no_mihomo

package smoke

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

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
