//go:build integration && !no_xray

package smoke

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
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

// A fake-ip filter entry xray would read as another matcher fails the start with
// the entry named. mihomo reads the filter only in a tunnel start, which the
// loopback suite cannot run; its grammar is held to mihomo's parser in mihomoconfig.
func TestSmoke_FakeIPFilterEntryItCannotCarryFailsStart(t *testing.T) {
	core.Initialize()

	upstream := startVlessServer(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Refused", testUUID, upstream)
	cases := []struct{ engine, entry string }{
		{"xray", "keyword:domain:example.com"},
	}
	for _, c := range cases {
		t.Run(c.engine+"/"+c.entry, func(t *testing.T) {
			ev := captureEvents(t)
			res := core.EngineStart(c.engine, core.EngineStartRequest{
				Config: link,
				DNSConfig: &dnsconfig.Config{
					Mode:         dnsconfig.ModeFakeIP,
					Servers:      []string{"1.1.1.1"},
					FakeIPFilter: []string{"+.lan", c.entry},
				},
				Opts: map[string]string{"proxyPort": strconv.Itoa(freePort(t))},
			})
			if res != core.ResultError {
				stopEngine(t, c.engine)
				t.Fatalf("EngineStart = %d, want error", res)
			}
			if msg := ev.waitFor(t, core.EngineError, 5*time.Second); !strings.Contains(msg, fmt.Sprintf("fakeIpFilter: %q", c.entry)) {
				t.Fatalf("EngineError = %q, want it to name the entry", msg)
			}
		})
	}
}
