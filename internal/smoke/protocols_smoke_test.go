//go:build integration && !no_mihomo

package smoke

import (
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
)

// directTunnel takes what a mihomo server inbound accepts straight to its
// destination - the role mihomo's own inbound tests give their TestTunnel -
// and counts the destination ports, so a test can tell its flow reached the
// server. The server shares nothing with the mihomo the engine runs.
type directTunnel struct {
	mu       sync.Mutex
	dests    map[uint16]int
	redirect string
}

func (d *directTunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	defer conn.Close()
	d.mu.Lock()
	d.dests[metadata.DstPort]++
	d.mu.Unlock()
	upstream, err := net.DialTimeout("tcp", d.destination(metadata.RemoteAddress()), 5*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
}

func (d *directTunnel) destination(addr string) string {
	if d.redirect != "" {
		return d.redirect
	}
	return addr
}

func (d *directTunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	dst := metadata.UDPAddr()
	go func() {
		defer packet.Drop()
		if dst == nil {
			return
		}
		conn, err := net.DialTimeout("udp", d.destination(dst.String()), time.Second)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write(packet.Data()); err != nil {
			return
		}
		var buf [2048]byte
		if n, err := conn.Read(buf[:]); err == nil {
			_, _ = packet.WriteBack(buf[:n], dst)
		}
	}()
}

func (*directTunnel) NatTable() C.NatTable { return nil }

func (d *directTunnel) reached(port int) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dests[uint16(port)]
}

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
	return listenInboundTo(t, in, "")
}

func listenInboundTo(t *testing.T, in C.InboundListener, redirect string) *directTunnel {
	t.Helper()
	tunnel := &directTunnel{dests: map[uint16]int{}, redirect: redirect}
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
		wrongCredentialLink: link("wrong"), pingEngine: "mihomo", reached: server.reached,
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
		wrongCredentialLink: link("wrong"), pingEngine: "mihomo", reached: server.reached,
	})
}
