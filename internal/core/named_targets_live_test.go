//go:build !no_xray && !no_mihomo

package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"sync"
	"testing"
	"time"

	xrayCore "github.com/xtls/xray-core/core"

	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
)

// exitServerEnv carries the config of a server the test binary runs as a
// process of its own, so that one server can resolve names nobody else in the
// test can: xray keeps its DNS client in a package variable, which a second
// instance in the same process would replace.
const exitServerEnv = "GLITCH_TEST_EXIT_SERVER_CONF"

func TestExitServerProcess(t *testing.T) {
	conf := os.Getenv(exitServerEnv)
	if conf == "" {
		t.Skip("runs only as a child of a test that starts an exit server")
	}
	server, err := xrayCore.StartInstance("json", []byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	select {}
}

// startExitServer runs a shadowsocks server whose own connections to the world
// leave from source, so an echo can tell which server a flow exited from. Its
// freedom outbound resolves the names in hosts, and the server runs in a
// process of its own so that nothing else in the test can.
func startExitServer(t *testing.T, source string, hosts map[string]string) (port int, stop func()) {
	t.Helper()
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	hostsJSON, _ := json.Marshal(hosts)
	conf := fmt.Sprintf(`{"dns":{"hosts":%s,"servers":["udp://127.0.0.1:1"]},"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"shadowsocks","settings":{"method":"chacha20-ietf-poly1305","password":"pw","network":"tcp"}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]},"streamSettings":{"sockopt":{"domainStrategy":"UseIP"}},"sendThrough":%q}]}`, hostsJSON, port, source)
	cmd := exec.Command(os.Args[0], "-test.run=^TestExitServerProcess$")
	cmd.Env = append(os.Environ(), exitServerEnv+"="+conf)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stop = func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }
	t.Cleanup(stop)
	for deadline := time.Now().Add(20 * time.Second); !listens(fmt.Sprintf("127.0.0.1:%d", port)); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("exit server did not start")
		}
	}
	return port, stop
}

// startRecordingForwarder relays to target and records who connected.
func startRecordingForwarder(t *testing.T, target string) (addr string, sources func() []string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var mu sync.Mutex
	var seen []string
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			seen = append(seen, c.RemoteAddr().(*net.TCPAddr).IP.String())
			mu.Unlock()
			go func() {
				defer c.Close()
				u, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer u.Close()
				go func() { _, _ = io.Copy(u, c) }()
				_, _ = io.Copy(c, u)
			}()
		}
	}()
	return l.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// startSourceEcho answers each connection with the address it came from.
func startSourceEcho(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, c.RemoteAddr().(*net.TCPAddr).IP.String())
			_ = c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// socksExit asks the session's SOCKS5 front for a connection to the echo and
// returns the address the echo saw.
func socksExit(proxyAddr, destination string, port int) (string, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return "", err
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(c, greeting); err != nil {
		return "", err
	}
	ip := net.ParseIP(destination).To4()
	if _, err := c.Write([]byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}); err != nil {
		return "", err
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		return "", err
	}
	if reply[1] != 0 {
		return "", fmt.Errorf("socks reply %d", reply[1])
	}
	body, err := io.ReadAll(c)
	if err == nil && len(body) == 0 {
		err = io.EOF
	}
	return string(body), err
}

// Over live servers and either engine: a named server exits from its own
// server, a chain's exit is dialled by hop 1 and never by the client, and with
// hop 1 down the chain fails instead of leaving through the pool or direct.
func TestNamedTargets_LiveOnBothEngines(t *testing.T) {
	for _, engine := range []string{"xray", "mihomo"} {
		t.Run(engine, func(t *testing.T) {
			if engine == "mihomo" {
				skipWhereMihomoRaces(t)
			}
			t.Setenv("GLITCH_SOCKS_READY_TIMEOUT_SEC", "20")
			echoPort := startSourceEcho(t)
			poolPort, _ := startExitServer(t, "127.0.0.2", nil)
			hop1Port, stopHop1 := startExitServer(t, "127.0.0.3", map[string]string{"hop2.test": "127.0.0.1"})
			hop2Port, _ := startExitServer(t, "127.0.0.4", nil)
			ownPort, _ := startExitServer(t, "127.0.0.5", nil)
			hop2Forwarder, hop2Callers := startRecordingForwarder(t, fmt.Sprintf("127.0.0.1:%d", hop2Port))
			// Only hop 1 can resolve this name: the client has no such host.
			_, hop2ForwarderPort, _ := net.SplitHostPort(hop2Forwarder)
			hop2Via := "hop2.test:" + hop2ForwarderPort
			link := func(addr, name string) string {
				return "ss://chacha20-ietf-poly1305:pw@" + addr + "#" + name
			}

			targets, _ := json.Marshal(map[string]any{
				"version": 1,
				"servers": []map[string]string{
					{"id": "h1", "link": link(fmt.Sprintf("127.0.0.1:%d", hop1Port), "h1")},
					{"id": "h2", "link": link(hop2Via, "h2")},
					{"id": "own", "link": link(fmt.Sprintf("127.0.0.1:%d", ownPort), "own")},
				},
				"chains": []map[string]any{{"id": "chain", "hops": []string{"h1", "h2"}}},
			})
			tiers, _ := json.Marshal([]map[string]any{{"routes": []map[string]any{
				{"to": "chain", "match": []string{"127.0.0.10"}},
				{"to": "own", "match": []string{"127.0.0.11"}},
			}}})
			proxyPort, proxyAddr := loopbackProxyPort(t)
			req := EngineStartRequest{
				Config: link(fmt.Sprintf("127.0.0.1:%d", poolPort), "pool"),
				Opts: map[string]string{
					"proxyPort":         proxyPort,
					"routingTiers":      string(tiers),
					"routingTargets":    string(targets),
					"geoAssetsDir":      mihomoSessionHome(t),
					"resolveExternalIp": "0",
					"livenessSec":       "300",
				},
			}

			x := &CoreController{}
			t.Cleanup(func() {
				x.stopStats()
				x.coreMutex.Lock()
				defer x.coreMutex.Unlock()
				x.endSessionLoops()
				x.xrayStopLocked()
				x.mihomoStopLocked()
			})
			life := recordLifecycle(t)
			start := x.HandleXrayStart
			if engine == "mihomo" {
				start = x.HandleMihomoStart
			}
			if res := start(req); res != glitchCoreResultSuccess {
				t.Fatalf("start = %d", res)
			}
			life.waitFor(t, EngineConnected, 1)

			for _, c := range []struct{ name, destination, exit string }{
				{"the pool", "127.0.0.12", "127.0.0.2"},
				{"a named server", "127.0.0.11", "127.0.0.5"},
				{"a chain", "127.0.0.10", "127.0.0.4"},
			} {
				got, err := socksExit(proxyAddr, c.destination, echoPort)
				if err != nil || got != c.exit {
					t.Errorf("%s: the echo saw %q (%v), want %s", c.name, got, err, c.exit)
				}
			}
			if callers := hop2Callers(); len(callers) != 1 || callers[0] != "127.0.0.3" {
				t.Errorf("the chain's exit was reached from %v, want from hop 1 (127.0.0.3) only", callers)
			}

			stopHop1()
			if got, err := socksExit(proxyAddr, "127.0.0.10", echoPort); err == nil {
				t.Errorf("with hop 1 down the chain reached the echo as %q", got)
			}
			if callers := hop2Callers(); len(callers) != 1 {
				t.Errorf("the chain's exit was reached again from %v with hop 1 down", callers)
			}
		})
	}
}
