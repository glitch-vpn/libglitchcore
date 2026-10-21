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

func TestSmoke_RoutingTiersOpt(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upstream := startVlessServer(t)
	echo := echoBody(t, "198.51.100.45")
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Tiers", testUUID, upstream)
	startProxyEngine(t, link, map[string]string{
		"routingTiers": `[{"proxy":["domain:vk.ru"]},{"direct":["domain:ru"],"block":["ads.example"]}]`,
		"probeUrl":     echo.URL,
		"ipv4EchoUrl":  echo.URL,
		"disableIPv6":  "1",
	})
	ev.waitFor(t, core.EngineConnected, 30*time.Second)
}

func TestSmoke_DomainStrategy(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upstream := startVlessServer(t)
	echo := echoBody(t, "198.51.100.46")
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#DS", testUUID, upstream)
	startProxyEngine(t, link, map[string]string{
		"domainStrategy": "IPIfNonMatch",
		"probeUrl":       echo.URL,
		"ipv4EchoUrl":    echo.URL,
		"disableIPv6":    "1",
	})
	ev.waitFor(t, core.EngineConnected, 30*time.Second)
}

func TestSmoke_DomainStrategyInvalidFailsStart(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upstream := startVlessServer(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#BadDS", testUUID, upstream)
	// The strategy is validated inside the async start path, so EngineStart
	// still returns success; the failure surfaces as EngineError.
	startProxyEngine(t, link, map[string]string{"domainStrategy": "bogus"})
	msg := ev.waitFor(t, core.EngineError, 10*time.Second)
	if !strings.Contains(msg, "invalid domainStrategy") {
		t.Fatalf("EngineError = %q, want invalid domainStrategy", msg)
	}
}

// Rules a start cannot carry intact fail it on every engine, before anything
// is armed: malformed tiers, the CSV rule keys, and a comma in a domain value,
// which would split a mihomo rule line and re-target it.
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
	}
	for _, engine := range []string{"xray", "mihomo"} {
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
