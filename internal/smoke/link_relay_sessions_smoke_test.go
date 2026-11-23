//go:build integration && !no_xray && !no_mihomo

package smoke

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	"github.com/glitch-vpn/libglitchcore/internal/linkrelay"
)

// A relay is not a session: it starts no engine and posts no lifecycle, server
// or exit-address event, and a session, a stop or another start leaves it carrying.
func TestSmoke_LinkRelayRunsBesideSessions(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)
	socksServer, socksPort := startSocksServer(t)
	echo := echoBody(t, "198.51.100.62")
	echoPort := echo.Listener.Addr().(*net.TCPAddr).Port
	upstream := startVlessServer(t)
	vless := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Beside", testUUID, upstream)

	info := openRelay(t, "xray", socksLinkTo("127.0.0.1", socksPort))
	if got := core.ActiveEngineID(); got != "" {
		t.Fatalf("a relay left engine %q running", got)
	}
	if body, err := fetchThroughRelay(info, echo.URL); err != nil || body != "198.51.100.62" {
		t.Fatalf("fetch with no session = %q, %v", body, err)
	}
	if events := countSessionEvents(ev); events != 0 {
		t.Errorf("a relay posted %d session events", events)
	}

	startEngineInProxyMode(t, "xray", vless, map[string]string{"resolveExternalIp": "0"}, nil)
	ev.waitFor(t, core.EngineConnected, 30*time.Second)
	if body, err := fetchThroughRelay(info, echo.URL); err != nil || body != "198.51.100.62" {
		t.Fatalf("fetch beside a proxy-mode session = %q, %v", body, err)
	}

	stopEngine(t, "xray")
	if body, err := fetchThroughRelay(info, echo.URL); err != nil || body != "198.51.100.62" {
		t.Fatalf("fetch after the session stopped = %q, %v", body, err)
	}

	startEngineInProxyMode(t, "mihomo", socksLinkTo("127.0.0.1", socksPort), map[string]string{"resolveExternalIp": "0"}, nil)
	if body, err := fetchThroughRelay(info, echo.URL); err != nil || body != "198.51.100.62" {
		t.Fatalf("fetch beside a mihomo proxy-mode session = %q, %v", body, err)
	}
	if socksServer.reached(echoPort) < 3 {
		t.Errorf("the link's server relayed %d of the relay's fetches, want 3 or more", socksServer.reached(echoPort))
	}

	linkrelay.Close(info.ID)
	if _, err := net.DialTimeout("tcp", relayAddress(info), time.Second); err == nil {
		t.Error("the listener outlived Close")
	}
	if core.EngineIsRunning("mihomo") != core.ResultSuccess {
		t.Error("closing the relay stopped the session")
	}
}

func countSessionEvents(ev *eventLog) int {
	n := 0
	for _, code := range []int32{
		core.EngineConnecting, core.EngineConnected, core.EngineError,
		core.EngineDisconnecting, core.EngineDisconnected, core.ServerEvent, core.IPEvent,
	} {
		n += len(ev.all(code))
	}
	return n
}
