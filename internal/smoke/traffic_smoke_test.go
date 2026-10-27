//go:build integration

package smoke

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

const trafficBodyBytes = 2 << 20

func fetchThroughSocks(t *testing.T, socksPort int, url string) int64 {
	t.Helper()
	dialer, err := xproxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, xproxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.(xproxy.ContextDialer).DialContext(ctx, network, addr)
		},
	}}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s through the engine: %v", url, err)
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body)
	return n
}

// mihomo reports what the tunnel proxied, as xray does: a download a direct
// rule sends past the proxy does not count, one through the proxy does.
func TestSmoke_MihomoTrafficCountsProxiedOnly(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	body := strings.Repeat("x", trafficBodyBytes)
	direct := echoBodyOn(t, "127.0.0.2", body).URL
	proxied := echoBodyOn(t, "127.0.0.1", body).URL
	upstream := startVlessServer(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Traffic", testUUID, upstream)
	mixedPort := startEngineInProxyMode(t, "mihomo", link, map[string]string{
		"routingTiers":      `[{"direct":["127.0.0.2/32"]}]`,
		"resolveExternalIp": "0",
		"disableIPv6":       "1",
	}, nil)
	ev.waitFor(t, core.EngineConnected, 30*time.Second)

	rxBefore, _, _ := core.EngineTraffic()
	if n := fetchThroughSocks(t, mixedPort, direct); n != trafficBodyBytes {
		t.Fatalf("direct download read %d bytes", n)
	}
	rxDirect, _, _ := core.EngineTraffic()
	if grew := rxDirect - rxBefore; grew > trafficBodyBytes/10 {
		t.Fatalf("a direct download of %d bytes added %d to rx", trafficBodyBytes, grew)
	}

	if n := fetchThroughSocks(t, mixedPort, proxied); n != trafficBodyBytes {
		t.Fatalf("proxied download read %d bytes", n)
	}
	rxProxied, _, _ := core.EngineTraffic()
	if grew := rxProxied - rxDirect; grew < trafficBodyBytes {
		t.Fatalf("a proxied download of %d bytes added only %d to rx", trafficBodyBytes, grew)
	}
}

// The Android notification reads traffic every second, a stop or not: a read
// racing the session's end answers at once.
func TestSmoke_XrayTrafficReadsDuringAStop(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	proxied := echoBodyOn(t, "127.0.0.1", strings.Repeat("x", trafficBodyBytes)).URL
	upstream := startVlessServer(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Traffic", testUUID, upstream)
	socksPort := startEngineInProxyMode(t, "xray", link, map[string]string{
		"resolveExternalIp": "0",
		"disableIPv6":       "1",
	}, nil)
	ev.waitFor(t, core.EngineConnected, 30*time.Second)
	if n := fetchThroughSocks(t, socksPort, proxied); n != trafficBodyBytes {
		t.Fatalf("proxied download read %d bytes", n)
	}
	if rx, _, running := core.EngineTraffic(); !running || rx < trafficBodyBytes {
		t.Fatalf("rx, running = %d, %v after a %d-byte download", rx, running, trafficBodyBytes)
	}

	var slowest atomic.Int64
	quit := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-quit:
					return
				default:
				}
				began := time.Now()
				core.EngineTraffic()
				took := int64(time.Since(began))
				for prev := slowest.Load(); took > prev && !slowest.CompareAndSwap(prev, took); prev = slowest.Load() {
				}
			}
		}()
	}
	stopEngine(t, "xray")
	close(quit)
	readers.Wait()

	if took := time.Duration(slowest.Load()); took > time.Second {
		t.Fatalf("a traffic read during the stop took %v", took)
	}
	if _, _, running := core.EngineTraffic(); running {
		t.Fatal("traffic reads a running engine after the stop")
	}
}

// A disconnect sent while the engine is still coming up ends the session
// rather than being refused and leaving the engine to come up anyway.
func TestSmoke_XrayStopDuringStartEndsTheSession(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upstream := startVlessServer(t)
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Traffic", testUUID, upstream)
	startEngineInProxyMode(t, "xray", link, map[string]string{
		"resolveExternalIp": "0",
		"disableIPv6":       "1",
	}, nil)
	if res := core.EngineStop("xray"); res != core.ResultSuccess {
		t.Fatalf("EngineStop during the start = %d", res)
	}
	ev.waitFor(t, core.EngineDisconnected, 30*time.Second)

	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if core.EngineIsRunning("xray") == core.ResultSuccess {
			t.Fatal("xray runs after a stop sent during its start")
		}
	}
	if _, connected := ev.last(core.EngineConnected); connected {
		t.Fatal("a start stopped before it came up reported connected")
	}
}
