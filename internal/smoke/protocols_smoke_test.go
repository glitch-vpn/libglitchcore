//go:build integration

package smoke

import (
	"strconv"
	"testing"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
)

const testProtocolPassword = "smoke-password"

// testCertificate returns a fresh self-signed pair and the hex SHA-256 a
// link pins it by.
func testCertificate(t *testing.T) (cert, key, pin string) {
	t.Helper()
	cert, key, pin, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	return cert, key, pin
}

func listenInbound(t *testing.T, in C.InboundListener) *directTunnel {
	t.Helper()
	tunnel := &directTunnel{dests: map[uint16]int{}}
	if err := in.Listen(tunnel); err != nil {
		t.Fatalf("%s server: %v", in.Name(), err)
	}
	t.Cleanup(func() { _ = in.Close() })
	return tunnel
}

func inboundOn(name string, port int) inbound.BaseOption {
	return inbound.BaseOption{NameStr: name, Listen: "127.0.0.1", Port: strconv.Itoa(port)}
}

// startTuicServer runs mihomo's TUIC v5 inbound on loopback.
func startTuicServer(t *testing.T) (server *directTunnel, port int, pin string) {
	t.Helper()
	cert, key, pin := testCertificate(t)
	port = freePort(t)
	in, err := inbound.NewTuic(&inbound.TuicOption{
		BaseOption:           inboundOn("tuic-smoke", port),
		Users:                map[string]string{testUUID: testProtocolPassword},
		Certificate:          cert,
		PrivateKey:           key,
		CongestionController: "bbr",
		ALPN:                 []string{"h3"},
	})
	if err != nil {
		t.Fatalf("tuic server: %v", err)
	}
	return listenInbound(t, in), port, pin
}

// startAnytlsServer runs mihomo's AnyTLS inbound on loopback.
func startAnytlsServer(t *testing.T) (server *directTunnel, port int, pin string) {
	t.Helper()
	cert, key, pin := testCertificate(t)
	port = freePort(t)
	in, err := inbound.NewAnyTLS(&inbound.AnyTLSOption{
		BaseOption:  inboundOn("anytls-smoke", port),
		Users:       map[string]string{"smoke": testProtocolPassword},
		Certificate: cert,
		PrivateKey:  key,
	})
	if err != nil {
		t.Fatalf("anytls server: %v", err)
	}
	return listenInbound(t, in), port, pin
}

func TestSmoke_Mihomo_TUIC(t *testing.T) {
	server, port, pin := startTuicServer(t)
	link := func(password string) string {
		return "tuic://" + testUUID + ":" + password + "@127.0.0.1:" + strconv.Itoa(port) +
			"?alpn=h3&congestion_control=bbr&udp_relay_mode=native&pcs=" + pin + "#TUIC%20Smoke"
	}
	assertSessionThrough(t, protocolSession{
		engine: "mihomo", link: link(testProtocolPassword), protocol: "tuic", port: port, name: "TUIC Smoke",
		wrongCredentialLink: link("wrong"), pingEngine: "mihomo", server: server,
	})
}

func TestSmoke_Mihomo_AnyTLS(t *testing.T) {
	server, port, pin := startAnytlsServer(t)
	link := func(password string) string {
		return "anytls://" + password + "@127.0.0.1:" + strconv.Itoa(port) +
			"/?sni=localhost&fp=chrome&pcs=" + pin + "#AnyTLS%20Smoke"
	}
	assertSessionThrough(t, protocolSession{
		engine: "mihomo", link: link(testProtocolPassword), protocol: "anytls", port: port, name: "AnyTLS Smoke",
		wrongCredentialLink: link("wrong"), pingEngine: "mihomo", server: server,
	})
}
