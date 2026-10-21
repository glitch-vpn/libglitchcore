//go:build integration

package smoke

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// Proxy mode with credentials carries TCP only, on both engines: SOCKS5 UDP
// cannot be tied to the login, so it is off. Without credentials the proxy is
// open, UDP included - which is also what shows the probe below can see a
// relay at all.
func TestSmoke_ProxyModeCredentialsCoverEverythingItCarries(t *testing.T) {
	core.Initialize()
	for _, engine := range []string{"xray", "mihomo"} {
		t.Run(engine, func(t *testing.T) {
			ev := captureEvents(t)
			upstream := startVlessServer(t)
			link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Udp", testUUID, upstream)
			echo := udpEchoServer(t)

			open := startEngineInProxyMode(t, engine, link, map[string]string{
				"resolveExternalIp": "0",
			}, nil)
			ev.waitFor(t, core.EngineConnected, 30*time.Second)
			if !socksUDPRelays(t, open, "", "", echo) {
				t.Fatal("the open proxy relayed no UDP; the probe cannot tell a relay from none")
			}
			stopEngine(t, engine)

			ev = captureEvents(t)
			authed := startEngineInProxyMode(t, engine, link, map[string]string{
				"resolveExternalIp": "0",
				"proxyUser":         "alice",
				"proxyPass":         "secret",
			}, nil)
			ev.waitFor(t, core.EngineConnected, 30*time.Second)
			if socksUDPRelays(t, authed, "alice", "secret", echo) {
				t.Fatal("the proxy with credentials relayed UDP")
			}
			if anonymousUDPRelays(t, authed, echo) {
				t.Fatal("the proxy with credentials relayed an anonymous UDP datagram")
			}
		})
	}
}

func udpEchoServer(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func socksUDPDatagram(dst *net.UDPAddr, payload []byte) []byte {
	b := []byte{0, 0, 0, 1}
	b = append(b, dst.IP.To4()...)
	b = binary.BigEndian.AppendUint16(b, uint16(dst.Port))
	return append(b, payload...)
}

// udpRoundTrip sends a SOCKS5 UDP datagram to relay and reports whether the
// echo came back through it.
func udpRoundTrip(relay string, dst *net.UDPAddr) bool {
	c, err := net.Dial("udp", relay)
	if err != nil {
		return false
	}
	defer c.Close()
	b := make([]byte, 2048)
	for i := 0; i < 5; i++ {
		_, _ = c.Write(socksUDPDatagram(dst, []byte("udp-probe")))
		_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		if n, err := c.Read(b); err == nil && strings.Contains(string(b[:n]), "udp-probe") {
			return true
		}
	}
	return false
}

// socksUDPRelays asks for a UDP association (with credentials when given)
// and, if granted, sends through the relay the server named.
func socksUDPRelays(t *testing.T, port int, user, pass string, dst *net.UDPAddr) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	method := byte(0)
	if user != "" {
		method = 2
	}
	_, _ = c.Write([]byte{5, 1, method})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil || reply[1] != method {
		t.Fatalf("method reply %v, %v; want %d", reply, err, method)
	}
	if user != "" {
		sub := append([]byte{1, byte(len(user))}, user...)
		sub = append(sub, byte(len(pass)))
		sub = append(sub, pass...)
		_, _ = c.Write(sub)
		if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0 {
			t.Fatalf("the proxy refused its own credentials: %v, %v", reply, err)
		}
	}
	_, _ = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0 || rep[3] != 1 {
		return false
	}
	bound := &net.UDPAddr{IP: net.IP(rep[4:8]), Port: int(binary.BigEndian.Uint16(rep[8:10]))}
	if bound.IP.IsUnspecified() {
		bound.IP = net.IPv4(127, 0, 0, 1)
	}
	if bound.Port == 0 {
		bound.Port = port
	}
	return udpRoundTrip(bound.String(), dst)
}

func anonymousUDPRelays(t *testing.T, port int, dst *net.UDPAddr) bool {
	t.Helper()
	return udpRoundTrip(fmt.Sprintf("127.0.0.1:%d", port), dst)
}
