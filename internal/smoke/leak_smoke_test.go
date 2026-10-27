//go:build integration

package smoke

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// openSockets counts the process's sockets where /proc says so; -1 elsewhere.
func openSockets() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	sockets := 0
	for _, e := range entries {
		if link, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && strings.HasPrefix(link, "socket:") {
			sockets++
		}
	}
	return sockets
}

// settledResources waits for both counts to stop falling: what a session that
// ended releases unwinds asynchronously, what it leaked never does.
func settledResources() (goroutines, sockets int) {
	goroutines, sockets = runtime.NumGoroutine(), openSockets()
	steady := 0
	for deadline := time.Now().Add(15 * time.Second); steady < 5 && time.Now().Before(deadline); {
		time.Sleep(200 * time.Millisecond)
		g, s := runtime.NumGoroutine(), openSockets()
		if g < goroutines || s < sockets {
			steady = 0
		} else {
			steady++
		}
		goroutines, sockets = min(g, goroutines), min(s, sockets)
	}
	return goroutines, sockets
}

// assertNothingLeft allows a little noise from the runtime, not a share per
// session.
func assertNothingLeft(t *testing.T, sessions, goroutinesGrown, socketsGrown int) {
	t.Helper()
	const noise = 2
	if goroutinesGrown > noise {
		t.Errorf("%d goroutines remain from %d stopped sessions", goroutinesGrown, sessions)
	}
	if socketsGrown > noise {
		t.Errorf("%d sockets remain from %d stopped sessions", socketsGrown, sessions)
	}
}

func socksDialer(t *testing.T, socksPort int) xproxy.ContextDialer {
	t.Helper()
	dialer, err := xproxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, xproxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	return dialer.(xproxy.ContextDialer)
}

// fetchOnce reads url through the proxy over a connection of its own.
func fetchOnce(t *testing.T, dialer xproxy.ContextDialer, url string, want int) {
	t.Helper()
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s through the engine: %v", url, err)
	}
	defer resp.Body.Close()
	if n, _ := io.Copy(io.Discard, resp.Body); n != int64(want) {
		t.Fatalf("download read %d bytes, want %d", n, want)
	}
}

// An app's connection that is still open when the session stops: the engine
// closes what it accepted, the app does not have to.
func holdOpen(t *testing.T, dialer xproxy.ContextDialer, hostPort string) net.Conn {
	t.Helper()
	conn, err := dialer.DialContext(t.Context(), "tcp", hostPort)
	if err != nil {
		t.Fatalf("dial %s through the engine: %v", hostPort, err)
	}
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatalf("read from %s through the engine: %v", hostPort, err)
	}
	return conn
}

func requireClosedByPeer(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		if _, err := conn.Read(make([]byte, 4096)); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatalf("an app's connection is still open after the session stopped")
			}
			return
		}
	}
}

// A stopped session leaves no goroutine or socket of its own, whatever
// traffic it carried and whatever connections its apps still held.
func TestSmoke_StoppedProxySessionLeavesNothingBehind(t *testing.T) {
	core.Initialize()
	body := strings.Repeat("x", 64<<10)
	target := echoBodyOn(t, "127.0.0.1", body)
	echoIP := echoBodyOn(t, "127.0.0.1", "203.0.113.7").URL
	upstream := startVlessServer(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Leak", testUUID, upstream)

	const cycles = 8
	for _, engine := range []string{"xray", "mihomo"} {
		t.Run(engine, func(t *testing.T) {
			ev := captureEvents(t)
			session := func() {
				port := startEngineInProxyMode(t, engine, link, map[string]string{
					"disableIPv6": "1",
					"probeUrl":    target.URL,
					"ipv4EchoUrl": echoIP,
				}, nil)
				ev.waitFor(t, core.EngineConnected, 30*time.Second)
				dialer := socksDialer(t, port)
				for range 3 {
					fetchOnce(t, dialer, target.URL, len(body))
				}
				var apps []net.Conn
				for range 3 {
					apps = append(apps, holdOpen(t, dialer, target.Listener.Addr().String()))
				}
				stopEngine(t, engine)
				for _, c := range apps {
					requireClosedByPeer(t, c)
				}
				ev.reset()
			}
			session() // one-time pools and listeners
			baseGoroutines, baseSockets := settledResources()
			for range cycles {
				session()
			}
			goroutines, sockets := settledResources()
			t.Logf("%s: goroutines %d -> %d, sockets %d -> %d over %d sessions",
				engine, baseGoroutines, goroutines, baseSockets, sockets, cycles)
			assertNothingLeft(t, cycles, goroutines-baseGoroutines, sockets-baseSockets)
		})
	}
}
