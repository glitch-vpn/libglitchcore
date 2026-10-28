//go:build integration

package smoke

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// echoAddr is a loopback address of its own, so a tier can reject the echo
// without touching the liveness probe on 127.0.0.1.
const echoAddr = "127.0.0.2"

// The routing tiers reject the echo's address; the exit-address echo must
// still reach it through the proxy. The probe stays allowed so the link comes
// up and arms the echo.
func TestSmoke_IPEchoBypassesRoutingTiers(t *testing.T) {
	for _, engine := range []string{"xray", "mihomo"} {
		t.Run(engine, func(t *testing.T) {
			core.Initialize()
			ev := captureEvents(t)

			upstream := startVlessServer(t)
			probe := echoBody(t, "probe")
			echo := echoBodyOn(t, echoAddr, "198.51.100.47")
			link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Echo", testUUID, upstream)
			startEngineInProxyMode(t, engine, link, map[string]string{
				"routingTiers": `[{"block":["` + echoAddr + `/32"]}]`,
				"probeUrl":     probe.URL,
				"ipv4EchoUrl":  echo.URL,
				"disableIPv6":  "1",
			}, nil)
			ev.waitFor(t, core.EngineConnected, 30*time.Second)

			var ip struct {
				IPv4      string `json:"ipv4"`
				IPv4Error string `json:"ipv4Error"`
			}
			if err := json.Unmarshal([]byte(ev.waitFor(t, core.IPEvent, 45*time.Second)), &ip); err != nil {
				t.Fatalf("IPEvent JSON: %v", err)
			}
			if ip.IPv4 != "198.51.100.47" {
				t.Fatalf("ipv4 = %q (err %q)", ip.IPv4, ip.IPv4Error)
			}
		})
	}
}

// The routing tiers reject the liveness probe's host; the link must still come
// up, which the exit echo's arrival shows.
func TestSmoke_LivenessProbeBypassesRoutingTiers(t *testing.T) {
	for _, engine := range []string{"xray", "mihomo"} {
		t.Run(engine, func(t *testing.T) {
			core.Initialize()
			ev := captureEvents(t)

			upstream := startVlessServer(t)
			probe := echoBodyOn(t, echoAddr, "probe")
			echo := echoBody(t, "198.51.100.48")
			link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Probe", testUUID, upstream)
			startEngineInProxyMode(t, engine, link, map[string]string{
				"routingTiers": `[{"block":["` + echoAddr + `/32"]}]`,
				"probeUrl":     probe.URL,
				"ipv4EchoUrl":  echo.URL,
				"disableIPv6":  "1",
			}, nil)
			ev.waitFor(t, core.EngineConnected, 30*time.Second)

			var ip struct {
				IPv4      string `json:"ipv4"`
				IPv4Error string `json:"ipv4Error"`
			}
			if err := json.Unmarshal([]byte(ev.waitFor(t, core.IPEvent, 45*time.Second)), &ip); err != nil {
				t.Fatalf("IPEvent JSON: %v", err)
			}
			if ip.IPv4 != "198.51.100.48" {
				t.Fatalf("ipv4 = %q (err %q): the probe reads as down", ip.IPv4, ip.IPv4Error)
			}
		})
	}
}
