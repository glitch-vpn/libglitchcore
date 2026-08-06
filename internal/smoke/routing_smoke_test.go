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

func TestSmoke_RoutingTiersMalformedFailsStart(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upstream := startVlessServer(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Bad", testUUID, upstream)
	res := core.EngineStart("xray", core.EngineStartRequest{
		Config: link,
		DNS:    "1.1.1.1",
		Opts: map[string]string{
			"proxyPort":    strconv.Itoa(freePort(t)),
			"routingTiers": `{"not":"an array"}`,
		},
	})
	if res != core.ResultError {
		t.Fatalf("EngineStart with malformed routingTiers = %d, want error", res)
	}
	if msg := ev.waitFor(t, core.EngineError, 5*time.Second); msg == "" {
		t.Fatal("no EngineError for malformed routingTiers")
	}
}
