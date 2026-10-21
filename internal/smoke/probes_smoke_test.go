//go:build integration

package smoke

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// mihomo's liveness probe and echo dial inside its tunnel, with no listener of
// their own. The echo only runs once the probe reports the link up, so the
// echo body in the IPEvent covers both.
func TestSmoke_Mihomo_ProbesDialInsideTheTunnel(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upstream := startVlessServer(t)
	echo := echoBody(t, "198.51.100.46")
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Probe", testUUID, upstream)
	startEngineInProxyMode(t, "mihomo", link, map[string]string{
		"probeUrl":    echo.URL,
		"ipv4EchoUrl": echo.URL,
		"disableIPv6": "1",
	}, nil)
	ev.waitFor(t, core.EngineConnected, 30*time.Second)

	var ip struct {
		IPv4      string `json:"ipv4"`
		IPv4Error string `json:"ipv4Error"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.IPEvent, 30*time.Second)), &ip); err != nil {
		t.Fatalf("IPEvent JSON: %v", err)
	}
	if ip.IPv4 != "198.51.100.46" {
		t.Fatalf("ipv4 = %q (err %q)", ip.IPv4, ip.IPv4Error)
	}
}
