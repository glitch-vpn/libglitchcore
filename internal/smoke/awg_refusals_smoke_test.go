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

// A start that cannot carry its AmneziaWG config as sent fails before anything
// is armed: proxy mode on awg, and a raw config inside a pool on awg and mihomo.
func TestSmoke_AwgConfigStartsRefused(t *testing.T) {
	core.Initialize()
	cases := []struct {
		name, engine string
		req          core.EngineStartRequest
		want         string
	}{
		{"awg proxy mode", "awg", core.EngineStartRequest{
			Config: refusedAwgConfig,
			Opts:   map[string]string{"proxyPort": "10808"},
		}, "proxyPort"},
		{"awg raw config in a pool", "awg", core.EngineStartRequest{
			Config: refusedAwgConfig + "\nawg://AAAA#second",
		}, "awg://"},
		{"mihomo raw config in a pool", "mihomo", core.EngineStartRequest{
			Config: "hysteria2://p@127.0.0.1:1#first\n" + refusedAwgConfig,
			Opts:   map[string]string{"proxyPort": "10808"},
		}, "awg://"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := captureEvents(t)
			if res := core.EngineStart(c.engine, c.req); res != core.ResultError {
				stopEngine(t, c.engine)
				t.Fatalf("EngineStart = %d, want error", res)
			}
			if msg := ev.waitFor(t, core.EngineError, 5*time.Second); !strings.Contains(msg, c.want) {
				t.Fatalf("EngineError = %q, want it to name %q", msg, c.want)
			}
		})
	}
}
