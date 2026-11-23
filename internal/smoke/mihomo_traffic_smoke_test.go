//go:build integration && !no_mihomo

package smoke

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// mihomo reports what the tunnel proxied, as xray does: a download a direct
// rule sends past the proxy does not count, one through the proxy does.
func TestSmoke_MihomoTrafficCountsProxiedOnly(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	body := strings.Repeat("x", trafficBodyBytes)
	direct := echoBodyOn(t, "127.0.0.2", body).URL
	proxied := echoBodyOn(t, "127.0.0.1", body).URL
	upstream := startVlessServer(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Traffic", testUUID, upstream)
	mixedPort := startEngineInProxyMode(t, "mihomo", link, map[string]string{
		"routingTiers":      `[{"direct":["127.0.0.2/32"]}]`,
		"resolveExternalIp": "0",
		"disableIPv6":       "1",
	}, nil)
	ev.waitFor(t, core.EngineConnected, 30*time.Second)

	rxBefore, _, _ := core.EngineTraffic()
	if n := fetchThroughSocks(t, mixedPort, direct); n != trafficBodyBytes {
		t.Fatalf("direct download read %d bytes", n)
	}
	rxDirect, _, _ := core.EngineTraffic()
	if grew := rxDirect - rxBefore; grew > trafficBodyBytes/10 {
		t.Fatalf("a direct download of %d bytes added %d to rx", trafficBodyBytes, grew)
	}

	if n := fetchThroughSocks(t, mixedPort, proxied); n != trafficBodyBytes {
		t.Fatalf("proxied download read %d bytes", n)
	}
	rxProxied, _, _ := core.EngineTraffic()
	if grew := rxProxied - rxDirect; grew < trafficBodyBytes {
		t.Fatalf("a proxied download of %d bytes added only %d to rx", trafficBodyBytes, grew)
	}
}
