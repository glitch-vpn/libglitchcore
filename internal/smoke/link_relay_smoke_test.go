//go:build integration && !no_mihomo

package smoke

import (
	"net"
	"strconv"
	"testing"

	xproxy "golang.org/x/net/proxy"

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
	for _, engine := range smokeEngines {
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
