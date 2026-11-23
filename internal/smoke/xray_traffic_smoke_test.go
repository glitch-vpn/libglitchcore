//go:build integration && !no_xray

package smoke

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

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
