//go:build integration

package smoke

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
)

// vlessRelay sits in front of a VLESS server and records the destination port
// each request names, so a test can tell the flow it sent from health checks.
type vlessRelay struct {
	port  int
	mu    sync.Mutex
	dests map[uint16]int
}

func startVlessRelay(t *testing.T, upstream int) *vlessRelay {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	r := &vlessRelay{port: l.Addr().(*net.TCPAddr).Port, dests: map[uint16]int{}}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go r.forward(c, upstream)
		}
	}()
	return r
}

// A request opens with version, UUID, addons length, addons, command and
// the destination port.
func (r *vlessRelay) forward(c net.Conn, upstream int) {
	defer c.Close()
	head := make([]byte, 18)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	rest := make([]byte, int(head[17])+3)
	if _, err := io.ReadFull(c, rest); err != nil {
		return
	}
	r.mu.Lock()
	r.dests[binary.BigEndian.Uint16(rest[len(rest)-2:])]++
	r.mu.Unlock()

	up, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(upstream))
	if err != nil {
		return
	}
	defer up.Close()
	if _, err := up.Write(append(head, rest...)); err != nil {
		return
	}
	go func() { _, _ = io.Copy(c, up) }()
	_, _ = io.Copy(up, c)
}

func (r *vlessRelay) reached(port int) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dests[uint16(port)]
}

// A remark naming one of mihomo's own names (its built-in outbounds and the
// GLOBAL selector) or the core's balancer group must not route the session
// anywhere but the server: a flow sent through the proxy reaches the server,
// alone and beside another link. The names are written out rather than taken
// from mihomoconfig, so the test does not share the list it checks.
func TestSmoke_Mihomo_RemarkNamingABuiltInReachesTheServer(t *testing.T) {
	names := []string{"GLOBAL", "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE", mihomoconfig.GroupTag}
	for _, name := range names {
		for _, count := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s/%d_links", name, count), func(t *testing.T) {
				core.Initialize()
				ev := captureEvents(t)
				relay := startVlessRelay(t, startVlessServer(t))
				probe := echoBody(t, "probe")
				target := echoBody(t, "target")
				link := func(remark string) string {
					return fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#%s", testUUID, relay.port, url.PathEscape(remark))
				}
				links := link(name)
				if count == 2 {
					links += "\n" + link("Other")
				}
				proxyPort := startEngineInProxyMode(t, "mihomo", links, map[string]string{
					"probeUrl":    probe.URL,
					"disableIPv6": "1",
				}, nil)
				ev.waitFor(t, core.EngineConnected, 30*time.Second)

				targetPort := target.Listener.Addr().(*net.TCPAddr).Port
				if _, err := socksConnect(proxyPort, "127.0.0.1", uint16(targetPort)); err != nil {
					t.Fatalf("socks request: %v", err)
				}
				deadline := time.Now().Add(5 * time.Second)
				for relay.reached(targetPort) == 0 {
					if time.Now().After(deadline) {
						t.Fatalf("no request for 127.0.0.1:%d reached the server behind a link named %q", targetPort, name)
					}
					time.Sleep(50 * time.Millisecond)
				}
			})
		}
	}
}
