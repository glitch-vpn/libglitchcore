//go:build integration

package smoke

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// Rules a start cannot carry intact fail it on every engine, before anything
// is armed: malformed tiers, the CSV rule keys, and a comma in a domain value,
// which would split a mihomo rule line and re-target it, a geo code no engine
// can look up, and a keyword xray would read as another matcher.
func TestSmoke_RulesItCannotCarryFailStart(t *testing.T) {
	core.Initialize()

	upstream := startVlessServer(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Refused", testUUID, upstream)
	cases := []struct {
		name, key, value, want string
	}{
		{"malformed tiers", "routingTiers", `{"not":"an array"}`, "routingTiers"},
		{"legacy key", "directRules", "geoip:ru", "directRules"},
		{"domain comma", "routingTiers", `[{"block":["domain:example.com,DIRECT"]}]`, "cannot contain a comma"},
		{"geoip code", "routingTiers", `[{"direct":["geoip:рф"]}]`, "invalid geoip code"},
		{"geosite code", "routingTiers", `[{"direct":["geosite:a,b"]}]`, "invalid geosite code"},
		{"keyword like a matcher", "routingTiers", `[{"block":["keyword:domain:example.com"]}]`, "another matcher"},
	}
	for _, engine := range smokeEngines {
		for _, c := range cases {
			t.Run(engine+"/"+c.name, func(t *testing.T) {
				ev := captureEvents(t)
				res := core.EngineStart(engine, core.EngineStartRequest{
					Config: link,
					DNS:    "1.1.1.1",
					Opts:   map[string]string{"proxyPort": strconv.Itoa(freePort(t)), c.key: c.value},
				})
				if res != core.ResultError {
					stopEngine(t, engine)
					t.Fatalf("EngineStart = %d, want error", res)
				}
				if msg := ev.waitFor(t, core.EngineError, 5*time.Second); !strings.Contains(msg, c.want) {
					t.Fatalf("EngineError = %q, want it to name %q", msg, c.want)
				}
			})
		}
	}
}
