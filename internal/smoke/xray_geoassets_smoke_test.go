//go:build integration && !no_xray

package smoke

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// A geo rule hard-fails cfg.Build() when the .dat files are unresolvable, so
// EngineConnected is itself the assertion that geoAssetsDir took effect - the
// test binary's exe dir (the env default) carries no .dat files.
func TestSmoke_GeoAssetsDirOpt_Xray(t *testing.T) {
	// xray's process-wide geo matchers can outlive the session that loaded them.
	const child = "GLITCH_SMOKE_XRAY_GEO_CHILD"
	if os.Getenv(child) == "" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$", "-test.timeout=45s")
		cmd.Env = append(os.Environ(), child+"=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("geo fixture subprocess: %v\n%s", err, out)
		}
		return
	}

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
