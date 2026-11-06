//go:build integration

package smoke

import (
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	"github.com/glitch-vpn/libglitchcore/internal/linkrelay"
)

func socksLinkTo(host string, port int) string {
	return "socks://" + base64Login(testProtocolPassword) + "@" + host + ":" + strconv.Itoa(port) + "#Relay"
}

func openRelay(t *testing.T, engine, link string) linkrelay.Info {
	t.Helper()
	info, err := linkrelay.Open(linkrelay.Request{Link: link, Engine: engine, IdleSec: 60})
	if err != nil {
		t.Fatalf("open relay on %q: %v", engine, err)
	}
	t.Cleanup(func() { linkrelay.Close(info.ID) })
	return info
}

func relayAddress(info linkrelay.Info) string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Port))
}

func fetchThroughRelay(info linkrelay.Info, url string) (string, error) {
	body, err := socksGet(relayAddress(info), &xproxy.Auth{User: info.User, Password: info.Password}, url)
	return string(body), err
}

// The server is named once by its address and once by a name the dial resolves,
// since a relay resolves a name at each dial and not when it opens.
func TestSmoke_LinkRelayFetchesThroughTheLinksServer(t *testing.T) {
	for _, engine := range []string{"xray", "mihomo"} {
		for _, host := range []string{"127.0.0.1", "localhost"} {
			t.Run(engine+"/"+host, func(t *testing.T) {
				server, port := startSocksServer(t)
				echo := echoBody(t, "198.51.100.61")
				echoPort := echo.Listener.Addr().(*net.TCPAddr).Port

				info := openRelay(t, engine, socksLinkTo(host, port))
				if info.Engine != engine {
					t.Errorf("relay engine = %q, want %q", info.Engine, engine)
				}
				body, err := fetchThroughRelay(info, echo.URL)
				if err != nil || body != "198.51.100.61" {
					t.Fatalf("fetch = %q, %v", body, err)
				}
				if server.reached(echoPort) == 0 {
					t.Error("the fetch did not pass through the link's server")
				}

				anonymous, err := xproxy.SOCKS5("tcp", relayAddress(info), nil, xproxy.Direct)
				if err != nil {
					t.Fatal(err)
				}
				if conn, err := anonymous.Dial("tcp", echo.Listener.Addr().String()); err == nil {
					conn.Close()
					t.Error("a client without the login was carried")
				}
			})
		}
	}
}

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
