//go:build integration

package smoke

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
)

// stubDNS is a minimal UDP responder: it answers every A query with one fixed
// address and records the names it was asked for, so a test can tell which of
// two resolvers the engine actually used.
type stubDNS struct {
	addr  string
	conn  net.PacketConn
	mu    sync.Mutex
	names []string
	reply net.IP
}

func startStubDNS(t *testing.T, reply string) *stubDNS {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &stubDNS{addr: conn.LocalAddr().String(), conn: conn, reply: net.ParseIP(reply).To4()}
	t.Cleanup(func() { _ = conn.Close() })
	go s.serve()
	return s
}

func (s *stubDNS) serve() {
	buf := make([]byte, 512)
	for {
		n, from, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		name, qEnd, ok := parseQuestion(buf[:n])
		if !ok {
			continue
		}
		s.mu.Lock()
		s.names = append(s.names, name)
		s.mu.Unlock()
		_, _ = s.conn.WriteTo(answerA(buf[:qEnd], s.reply), from)
	}
}

func (s *stubDNS) asked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.names...)
}

// parseQuestion returns the QNAME of a single-question query and the offset
// just past the question section.
func parseQuestion(msg []byte) (string, int, bool) {
	if len(msg) < 13 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return "", 0, false
	}
	var labels []string
	i := 12
	for i < len(msg) {
		l := int(msg[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 || i+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[i:i+l]))
		i += l
	}
	if i+4 > len(msg) {
		return "", 0, false
	}
	return strings.Join(labels, "."), i + 4, true
}

// answerA echoes the question back with one A record appended.
func answerA(query []byte, ip net.IP) []byte {
	resp := append([]byte(nil), query...)
	resp[2] |= 0x80 // QR: response
	binary.BigEndian.PutUint16(resp[6:8], 1)
	rr := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4}
	return append(append(resp, rr...), ip...)
}

// The engine resolves a direct-routed name when freedom dials it, and that
// lookup must reach directServers - not the general list. Proxy mode keeps the
// whole exchange on loopback: SOCKS in, in-process VLESS out.
func TestSmoke_DirectServersAnswerDirectNames(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upstream := startVlessServer(t)
	echo := echoBody(t, "198.51.100.47")
	general := startStubDNS(t, "198.51.100.10")
	direct := startStubDNS(t, "127.0.0.1")

	core.ApplyStatusVerbosity(2)
	t.Cleanup(func() { core.ApplyStatusVerbosity(-1) })

	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#DnsSplit", testUUID, upstream)
	proxyPort := startProxyEngineDNS(t, link, map[string]string{
		"routingTiers": `[{"direct":["domain:direct.test"]}]`,
		"disableIPv6":  "1",
		// The probe would otherwise resolve through the general stub and blur
		// the assertion.
		"probeUrl":          echo.URL,
		"resolveExternalIp": "0",
	}, &dnsconfig.Config{
		Mode:    dnsconfig.ModeFakeIP,
		Servers: []string{general.addr},
		// A filter is set on purpose: its exclusion server used to answer every
		// name ahead of fakedns, which both disabled fake-ip and starved the
		// direct resolvers.
		FakeIPFilter:  []string{"domain:lan"},
		DirectServers: []string{direct.addr},
	})
	ev.waitFor(t, core.EngineConnected, 30*time.Second)

	// A direct-routed hostname sent through the SOCKS inbound: xray routes it
	// direct and freedom resolves it, which is the lookup under test.
	if status, err := socksConnect(proxyPort, "direct.test", 80); err != nil {
		t.Fatalf("socks connect (status %d): %v", status, err)
	}

	// Assert the server order xray picked for the name, from its own log:
	// a loopback stub cannot receive the datagram itself, because on Windows
	// the direct outbound binds the physical NIC as its source.
	line := ev.waitForLog(t, func(msg string) bool {
		return strings.Contains(msg, "direct.test") && strings.Contains(msg, "will use DNS in order")
	}, 10*time.Second)
	if line == "" {
		t.Fatalf("xray never resolved direct.test (direct stub saw %v, general saw %v)",
			direct.asked(), general.asked())
	}
	fake, d, g := strings.Index(line, "FakeDNS"), strings.Index(line, direct.addr), strings.Index(line, general.addr)
	if d < 0 || g < 0 {
		t.Fatalf("both resolvers must be offered for direct.test: %s", line)
	}
	// fakedns first keeps the app on fake IPs; the direct resolver ahead of the
	// general one is what makes a direct-routed name resolve through it.
	if fake < 0 || fake > d {
		t.Fatalf("fakedns must stay ahead of the direct resolver: %s", line)
	}
	if d > g {
		t.Fatalf("direct resolver must precede the general one: %s", line)
	}
}
