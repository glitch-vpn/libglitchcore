//go:build integration && !no_xray && !no_mihomo

package smoke

import (
	"strconv"
	"strings"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/pinger"
)

func TestSmoke_HTTPProxy(t *testing.T) {
	t.Run("http", func(t *testing.T) {
		server, port, _ := startHTTPProxyServer(t, false)
		addr := "@127.0.0.1:" + strconv.Itoa(port)
		assertSessionThrough(t, protocolSession{
			engine: "xray", link: "http://" + base64Login(testProtocolPassword) + addr + "#HTTP%20Smoke",
			protocol: "http", port: port, name: "HTTP Smoke",
			wrongCredentialLink: "http://" + base64Login("wrong") + addr, pingEngine: "xray", reached: server.reached,
		})
	})
	t.Run("https", func(t *testing.T) {
		server, port, pin := startHTTPProxyServer(t, true)
		link := func(password string) string {
			return "https://" + testProxyUser + ":" + password + "@127.0.0.1:" + strconv.Itoa(port) + "?sni=localhost&pcs=" + pin + "#HTTPS%20Smoke"
		}
		assertSessionThrough(t, protocolSession{
			engine: "xray", link: link(testProtocolPassword), protocol: "http", port: port, name: "HTTPS Smoke",
			wrongCredentialLink: link("wrong"), pingEngine: "xray", reached: server.reached,
		})
	})
}

// An https proxy whose certificate is self-signed answers no ping without its
// pin, nor with another one.
func TestSmoke_HTTPSProxyChecksTheCertificate(t *testing.T) {
	_, port, pin := startHTTPProxyServer(t, true)
	echo := echoBody(t, "198.51.100.48")
	base := "https://" + testProxyUser + ":" + testProtocolPassword + "@127.0.0.1:" + strconv.Itoa(port) + "?sni=localhost"
	wrongPin := strings.Repeat("0", len(pin))
	results := pinger.Measure(pinger.Request{
		Engine:    "xray",
		Links:     []string{base + "&pcs=" + pin, base, base + "&pcs=" + wrongPin},
		ProbeURL:  echo.URL,
		TimeoutMs: 5000,
	})
	if !results[0].Alive {
		t.Fatalf("the pinned link answered no ping: %+v", results[0])
	}
	for _, r := range results[1:] {
		if r.Alive {
			t.Fatalf("link %d reached the proxy without its certificate's pin: %+v", r.Index, r)
		}
	}
}
