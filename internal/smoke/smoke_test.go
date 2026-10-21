//go:build integration

// Package smoke runs the engines end-to-end in-process: an xray-core VLESS
// server on loopback, the controller in proxy mode against it, and assertions
// on the events the FFI would deliver to Dart. No TUN, no admin, no network
// beyond 127.0.0.1.
//
//	CGO_ENABLED=0 go test -tags="integration with_gvisor" ./internal/smoke/ -v
package smoke

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	xrayCore "github.com/xtls/xray-core/core"
)

// The suite must never talk to a real GlitchVpnCore Windows service - with the
// IPC default on, engine stop / stats calls would reach the user's live
// session.
func TestMain(m *testing.M) {
	core.SetServiceIPC(false)
	os.Exit(m.Run())
}

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// freePort probes UDP as well: xray binds both, and a TCP-only probe can hand
// back a port inside a Windows Hyper-V/WinNAT UDP exclusion range, which then
// fails the engine start.
func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		u, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		_ = u.Close()
		return port
	}
	t.Fatal("no port free on both TCP and UDP")
	return 0
}

func startVlessServer(t *testing.T) int {
	t.Helper()
	port := freePort(t)
	cfg := fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": %d,
			"protocol": "vless",
			"settings": {"clients": [{"id": %q}], "decryption": "none"}
		}],
		"outbounds": [{"protocol": "freedom"}]
	}`, port, testUUID)
	inst, err := xrayCore.StartInstance("json", []byte(cfg))
	if err != nil {
		t.Fatalf("vless server: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return port
}

func echoBody(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

type eventLog struct {
	mu     sync.Mutex
	byCode map[int32][]string
}

func captureEvents(t *testing.T) *eventLog {
	t.Helper()
	ev := &eventLog{byCode: map[int32][]string{}}
	core.SetStatusSink(func(code int32, msg string) {
		ev.mu.Lock()
		ev.byCode[code] = append(ev.byCode[code], msg)
		ev.mu.Unlock()
		t.Logf("event %d: %s", code, msg)
	})
	t.Cleanup(func() { core.SetStatusSink(nil) })
	return ev
}

func (e *eventLog) reset() {
	e.mu.Lock()
	e.byCode = map[int32][]string{}
	e.mu.Unlock()
}

func (e *eventLog) all(code int32) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.byCode[code]...)
}

func (e *eventLog) last(code int32) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	msgs := e.byCode[code]
	if len(msgs) == 0 {
		return "", false
	}
	return msgs[len(msgs)-1], true
}

// waitForLog is the escape hatch for behaviour the event surface does not
// report (which resolver the DNS module picked, say). It needs
// core.ApplyStatusVerbosity(2) with a restore, and it reads engine log text.
func (e *eventLog) waitForLog(t *testing.T, match func(string) bool, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		for _, msg := range e.all(core.LogEvent) {
			if match(msg) {
				return msg
			}
		}
		if time.Now().After(deadline) {
			return ""
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (e *eventLog) waitFor(t *testing.T, code int32, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if msg, ok := e.last(code); ok {
			return msg
		}
		time.Sleep(50 * time.Millisecond)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	t.Fatalf("no event %d within %s; captured: %v", code, timeout, e.byCode)
	return ""
}

func stopEngine(t *testing.T, id string) {
	t.Helper()
	core.EngineStop(id)
	deadline := time.Now().Add(10 * time.Second)
	for core.EngineIsRunning(id) == core.ResultSuccess && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
}

func startProxyEngine(t *testing.T, links string, extraOpts map[string]string) {
	t.Helper()
	startProxyEngineDNS(t, links, extraOpts, nil)
}

// startProxyEngineDNS returns the loopback SOCKS port so a test can drive
// traffic through the engine it just started.
func startProxyEngineDNS(t *testing.T, links string, extraOpts map[string]string, dns *dnsconfig.Config) int {
	t.Helper()
	return startEngineInProxyMode(t, "xray", links, extraOpts, dns)
}

func startEngineInProxyMode(t *testing.T, engine, links string, extraOpts map[string]string, dns *dnsconfig.Config) int {
	t.Helper()
	// The default 5s SOCKS-ready budget can expire on a cold first run.
	t.Setenv("GLITCH_SOCKS_READY_TIMEOUT_SEC", "20")
	proxyPort := freePort(t)
	opts := map[string]string{
		"proxyPort": strconv.Itoa(proxyPort),
	}
	for k, v := range extraOpts {
		opts[k] = v
	}
	res := core.EngineStart(engine, core.EngineStartRequest{
		Config:    links,
		TunFD:     0,
		DNS:       "1.1.1.1",
		LogLevel:  3, // only reaches the sink when the test raises verbosity
		Opts:      opts,
		DNSConfig: dns,
	})
	if res != core.ResultSuccess {
		t.Fatalf("EngineStart %s = %d", engine, res)
	}
	t.Cleanup(func() { stopEngine(t, engine) })
	return proxyPort
}

// socksConnect asks the loopback SOCKS inbound for a hostname, which is what
// makes xray route and then resolve it. The CONNECT reply status is ignored:
// xray answers before dialing and only dials on the first payload, so the
// write below is what triggers the resolution under test.
func socksConnect(port int, host string, dstPort uint16) (byte, error) {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return 0, err
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(c, greeting); err != nil {
		return 0, err
	}
	if greeting[1] != 0 {
		return 0, fmt.Errorf("socks auth method %d, want none", greeting[1])
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, dstPort)
	if _, err := c.Write(req); err != nil {
		return 0, err
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(c, reply); err != nil {
		return 0, err
	}
	if _, err := c.Write([]byte("GET / HTTP/1.0\r\nHost: " + host + "\r\n\r\n")); err != nil {
		return reply[1], err
	}
	_, _ = io.ReadFull(c, make([]byte, 1))
	return reply[1], nil
}

// SOCKS inbound -> vless client -> in-process vless server -> freedom ->
// loopback echo; the IPEvent can only carry the echo body via that path.
func TestSmoke_ProxyMode_ServerAndIPEvents(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upstream := startVlessServer(t)
	echoV4 := echoBody(t, "198.51.100.42")
	echoV6 := echoBody(t, "2001:db8::42")

	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Smoke%%20A", testUUID, upstream)
	startProxyEngine(t, link, map[string]string{
		"probeUrl":    echoV4.URL,
		"ipv4EchoUrl": echoV4.URL,
		"ipv6EchoUrl": echoV6.URL,
	})

	ev.waitFor(t, core.EngineConnected, 30*time.Second)

	var sel struct {
		Engine   string `json:"engine"`
		Strategy string `json:"strategy"`
		Total    int    `json:"total"`
		Selected *struct {
			Index    int    `json:"index"`
			Name     string `json:"name"`
			Host     string `json:"host"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"selected"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.ServerEvent, 15*time.Second)), &sel); err != nil {
		t.Fatalf("ServerEvent JSON: %v", err)
	}
	if sel.Engine != "xray" || sel.Total != 1 || sel.Strategy != "" {
		t.Fatalf("selection = %+v", sel)
	}
	if sel.Selected == nil || sel.Selected.Host != "127.0.0.1" || sel.Selected.Port != upstream ||
		sel.Selected.Name != "Smoke A" || sel.Selected.Protocol != "vless" {
		t.Fatalf("selected = %+v", sel.Selected)
	}

	// First liveness probe (and the fetch behind it) fires after the 5s quick
	// interval.
	var ip struct {
		IPv4      string `json:"ipv4"`
		IPv6      string `json:"ipv6"`
		IPv4Error string `json:"ipv4Error"`
		IPv6Error string `json:"ipv6Error"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.IPEvent, 30*time.Second)), &ip); err != nil {
		t.Fatalf("IPEvent JSON: %v", err)
	}
	if ip.IPv4 != "198.51.100.42" {
		t.Fatalf("ipv4 = %q (err %q)", ip.IPv4, ip.IPv4Error)
	}
	if ip.IPv6 != "2001:db8::42" {
		t.Fatalf("ipv6 = %q (err %q)", ip.IPv6, ip.IPv6Error)
	}
}

// A fresh status sink (new isolate after hot restart / app relaunch) must get
// the live session's view replayed without calling connect().
func TestSmoke_ReplayOnAttach(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upstream := startVlessServer(t)
	echo := echoBody(t, "198.51.100.44")
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Replay", testUUID, upstream)
	startProxyEngine(t, link, map[string]string{
		"probeUrl":    echo.URL,
		"ipv4EchoUrl": echo.URL,
		"disableIPv6": "1",
	})
	ev.waitFor(t, core.EngineConnected, 30*time.Second)
	ev.waitFor(t, core.ServerEvent, 15*time.Second)
	ev.waitFor(t, core.IPEvent, 30*time.Second)

	fresh := captureEvents(t) // registering the sink triggers the replay
	fresh.waitFor(t, core.EngineConnected, 10*time.Second)
	if sel := fresh.waitFor(t, core.ServerEvent, 10*time.Second); !strings.Contains(sel, `"name":"Replay"`) {
		t.Fatalf("replayed selection = %s", sel)
	}
	if ip := fresh.waitFor(t, core.IPEvent, 10*time.Second); !strings.Contains(ip, "198.51.100.44") {
		t.Fatalf("replayed ip = %s", ip)
	}
	fresh.waitFor(t, core.StatsEvent, 10*time.Second)
}

func TestSmoke_Balancer_ServerEventPool(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upA := startVlessServer(t)
	upB := startVlessServer(t)
	echo := echoBody(t, "198.51.100.43")

	links := fmt.Sprintf(
		"vless://%s@127.0.0.1:%d?security=none&type=tcp#Pool%%20A\nvless://%s@127.0.0.1:%d?security=none&type=tcp#Pool%%20B",
		testUUID, upA, testUUID, upB,
	)
	startProxyEngine(t, links, map[string]string{
		"balancerStrategy": "leastping",
		"probeUrl":         echo.URL,
		"ipv4EchoUrl":      echo.URL,
		"disableIPv6":      "1",
	})

	ev.waitFor(t, core.EngineConnected, 30*time.Second)

	var sel struct {
		Strategy string `json:"strategy"`
		Total    int    `json:"total"`
		Selected *struct {
			Index int    `json:"index"`
			Name  string `json:"name"`
		} `json:"selected"`
		Servers []struct {
			Index int    `json:"index"`
			Name  string `json:"name"`
			Port  int    `json:"port"`
		} `json:"servers"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.ServerEvent, 15*time.Second)), &sel); err != nil {
		t.Fatalf("ServerEvent JSON: %v", err)
	}
	if sel.Strategy != "leastping" || sel.Total != 2 || len(sel.Servers) != 2 {
		t.Fatalf("selection = %+v", sel)
	}
	if sel.Servers[0].Name != "Pool A" || sel.Servers[1].Name != "Pool B" ||
		sel.Servers[0].Port != upA || sel.Servers[1].Port != upB {
		t.Fatalf("pool = %+v", sel.Servers)
	}
	// leastping reports the fallback (first outbound) until the observatory
	// has a verdict.
	if sel.Selected == nil {
		t.Fatal("no initial selected for leastping")
	}

	var ip struct {
		IPv4      string `json:"ipv4"`
		IPv6Error string `json:"ipv6Error"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.IPEvent, 30*time.Second)), &ip); err != nil {
		t.Fatalf("IPEvent JSON: %v", err)
	}
	if ip.IPv4 != "198.51.100.43" {
		t.Fatalf("ipv4 = %q", ip.IPv4)
	}
	if ip.IPv6Error != "disabled" {
		t.Fatalf("ipv6Error = %q, want disabled", ip.IPv6Error)
	}
}
