//go:build integration

package smoke

import (
	"strings"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

const refusedAwgConfig = `[Interface]
PrivateKey = UqX1+GfjpHXk0TC7KI4s11YRL3WKJudP0ebnvmVu4aY=
Address = 10.66.0.2/32

[Peer]
PublicKey = ys6ln6BOSOotjcRKGYel/HW/HQ65w+bAg8ac9VVtLWo=
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:9`

// A raw [Interface] config cannot share a pool with other links: the start
// fails before anything is armed, naming the awg:// form each config can take.
func TestSmoke_RawWireGuardConfigInAPoolRefused(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)
	res := core.EngineStart("mihomo", core.EngineStartRequest{
		Config: "hysteria2://p@127.0.0.1:1#first\n" + refusedAwgConfig,
		Opts:   map[string]string{"proxyPort": "10808"},
	})
	if res != core.ResultError {
		stopEngine(t, "mihomo")
		t.Fatalf("EngineStart = %d, want error", res)
	}
	if msg := ev.waitFor(t, core.EngineError, 5*time.Second); !strings.Contains(msg, "awg://") {
		t.Fatalf("EngineError = %q, want it to name awg://", msg)
	}
}
