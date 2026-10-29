//go:build integration

package smoke

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	"github.com/glitch-vpn/libglitchcore/internal/pinger"
)

const testProxyUser = "alice"

func proxyUsers() inbound.AuthUsers {
	return inbound.AuthUsers{{Username: testProxyUser, Password: testProtocolPassword}}
}

// startSocksServer runs mihomo's SOCKS5 inbound on loopback with a login.
func startSocksServer(t *testing.T) (server *directTunnel, port int) {
	t.Helper()
	port = freePort(t)
	in, err := inbound.NewSocks(&inbound.SocksOption{BaseOption: inboundOn("socks-smoke", port), Users: proxyUsers()})
	if err != nil {
		t.Fatalf("socks server: %v", err)
	}
	return listenInbound(t, in), port
}

// startHTTPProxyServer runs mihomo's HTTP proxy inbound on loopback with a
// login, over TLS when tls is set; pin is the certificate's then.
func startHTTPProxyServer(t *testing.T, tls bool) (server *directTunnel, port int, pin string) {
	t.Helper()
	port = freePort(t)
	opt := &inbound.HTTPOption{BaseOption: inboundOn("http-smoke", port), Users: proxyUsers()}
	if tls {
		opt.Certificate, opt.PrivateKey, pin = testCertificate(t)
	}
	in, err := inbound.NewHTTP(opt)
	if err != nil {
		t.Fatalf("http server: %v", err)
	}
	return listenInbound(t, in), port, pin
}

// base64Login is the userinfo v2rayN and v2rayNG write: base64 of user:pass.
func base64Login(password string) string {
	return base64.StdEncoding.EncodeToString([]byte(testProxyUser + ":" + password))
}

func TestSmoke_SocksProxy(t *testing.T) {
	for _, engine := range []string{"xray", "mihomo"} {
		t.Run(engine, func(t *testing.T) {
			server, port := startSocksServer(t)
			addr := "@127.0.0.1:" + strconv.Itoa(port)
			assertSessionThrough(t, protocolSession{
				engine: engine, link: "socks://" + base64Login(testProtocolPassword) + addr + "#Socks%20Smoke",
				protocol: "socks", port: port, name: "Socks Smoke",
				wrongCredentialLink: "socks5://" + testProxyUser + ":wrong" + addr, pingEngine: "xray", server: server,
			})
		})
	}
}

func TestSmoke_HTTPProxy(t *testing.T) {
	t.Run("http", func(t *testing.T) {
		server, port, _ := startHTTPProxyServer(t, false)
		addr := "@127.0.0.1:" + strconv.Itoa(port)
		assertSessionThrough(t, protocolSession{
			engine: "xray", link: "http://" + base64Login(testProtocolPassword) + addr + "#HTTP%20Smoke",
			protocol: "http", port: port, name: "HTTP Smoke",
			wrongCredentialLink: "http://" + base64Login("wrong") + addr, pingEngine: "xray", server: server,
		})
	})
	t.Run("https", func(t *testing.T) {
		server, port, pin := startHTTPProxyServer(t, true)
		link := func(password string) string {
			return "https://" + testProxyUser + ":" + password + "@127.0.0.1:" + strconv.Itoa(port) + "?sni=localhost&pcs=" + pin + "#HTTPS%20Smoke"
		}
		assertSessionThrough(t, protocolSession{
			engine: "xray", link: link(testProtocolPassword), protocol: "http", port: port, name: "HTTPS Smoke",
			wrongCredentialLink: link("wrong"), pingEngine: "xray", server: server,
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

// An http proxy has no UDP. xray drops a datagram meant for it; mihomo would
// send it direct, so it refuses the link.
func TestSmoke_HTTPProxyCarriesNoUDP(t *testing.T) {
	core.Initialize()
	_, port, _ := startHTTPProxyServer(t, false)
	link := "http://" + base64Login(testProtocolPassword) + "@127.0.0.1:" + strconv.Itoa(port) + "#NoUDP"
	echo := udpEchoServer(t)

	t.Run("xray", func(t *testing.T) {
		ev := captureEvents(t)
		proxyPort := startEngineInProxyMode(t, "xray", link, map[string]string{"resolveExternalIp": "0"}, nil)
		ev.waitFor(t, core.EngineConnected, 30*time.Second)
		if socksUDPRelays(t, proxyPort, "", "", echo) {
			t.Fatal("a UDP datagram meant for the http proxy reached the echo")
		}
	})
	t.Run("mihomo", func(t *testing.T) {
		ev := captureEvents(t)
		startExpectingError(t, ev, "mihomo", link)
		if msg, _ := ev.last(core.EngineError); !strings.Contains(msg, "UDP") {
			t.Fatalf("EngineError = %q, want the http proxy refused for its UDP", msg)
		}
	})
}
