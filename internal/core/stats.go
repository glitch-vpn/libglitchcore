package core

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"runtime/metrics"
	"time"
)

// goRuntimeMemBytes is the Go runtime's OS footprint (mapped, not yet released),
// isolated from the Flutter host sharing the process. Uses runtime/metrics to
// avoid ReadMemStats' stop-the-world; excludes C allocations. In the Windows
// service (no Flutter) it approximates process RSS - the iOS-NE budget proxy.
func goRuntimeMemBytes() uint64 {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	metrics.Read(samples)
	if samples[0].Value.Kind() != metrics.KindUint64 || samples[1].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	total, released := samples[0].Value.Uint64(), samples[1].Value.Uint64()
	if released > total {
		return total
	}
	return total - released
}

func (x *CoreController) startStats(interval time.Duration) {
	x.stopStats()
	if useServiceIPC {
		if err := serviceListenStats(interval); err != nil {
			log.Printf("[IPC] listen stats failed: %v", err)
		}
		return
	}
	// Local refs so the goroutine never reads fields after stopStats().
	quit := make(chan struct{})
	done := make(chan struct{})
	ticker := time.NewTicker(interval)
	x.statsMu.Lock()
	x.statsQuit = quit
	x.statsDone = done
	x.statsTicker = ticker
	x.statsMu.Unlock()
	log.Printf("[Generic] Started listenStats with interval %s", interval)
	go func(t *time.Ticker, q <-chan struct{}) {
		defer close(done)
		for {
			select {
			case <-t.C:
				x.statsMu.Lock()
				select {
				case <-q:
					x.statsMu.Unlock()
					log.Println("[Generic] stopStats triggered")
					return
				default:
				}
				rx, tx, running := x.readEngineTraffic()
				if !running {
					x.statsMu.Unlock()
					continue
				}
				durationMs := int64(0)
				connectedAt := x.connectedAtUnixMs.Load()
				if connectedAt > 0 {
					durationMs = time.Now().UnixMilli() - connectedAt
					if durationMs < 0 {
						durationMs = 0
					}
				}
				// Engine-process RSS (on Windows the service builds this event, so it's
				// the right process); the iOS-NE budget proxy.
				rss := currentProcessRSSBytes()
				goMem := goRuntimeMemBytes()
				link := ""
				if up, probeMs, known := x.livenessSnapshot(); known {
					link = fmt.Sprintf(",\"linkUp\":%t,\"probeMs\":%d", up, probeMs)
				}
				// Leak diagnostics for the slow "everything stops after hours" bug: a
				// rising goroutine or handle count over a long session flags a leak
				// (handles = sockets on Windows / fds on Linux). Log-only.
				log.Printf("[Generic] Stats: rx=%d, tx=%d, durationMs=%d, rss=%d, goMem=%d, goroutines=%d, handles=%d%s",
					rx, tx, durationMs, rss, goMem, runtime.NumGoroutine(), currentProcessHandleCount(), link)
				msg := fmt.Sprintf("{\"rx\":%d,\"tx\":%d,\"durationMs\":%d,\"rssBytes\":%d,\"goMemBytes\":%d%s}", rx, tx, durationMs, rss, goMem, link)
				x.emitStatus(StatsEvent, msg)
				x.statsMu.Unlock()
			case <-q:
				log.Println("[Generic] stopStats triggered")
				return
			}
		}
	}(ticker, quit)
}

func (x *CoreController) stopStats() {
	if useServiceIPC {
		if err := serviceStopStats(); err != nil {
			log.Printf("[IPC] stop stats failed: %v", err)
		}
		return
	}
	log.Println("[Generic] stopStats")
	x.statsMu.Lock()
	if x.statsQuit != nil {
		close(x.statsQuit)
		x.statsQuit = nil
	}
	if x.statsTicker != nil {
		x.statsTicker.Stop()
		x.statsTicker = nil
	}
	done := x.statsDone
	x.statsDone = nil
	x.statsMu.Unlock()
	if done != nil {
		<-done
	}
	x.stopHealthCheck()
}

func (x *CoreController) startHealthCheck(interval time.Duration) {
	x.stopHealthCheck()
	quit := make(chan struct{})
	x.healthCheckQuit = quit
	log.Printf("[HealthCheck] Started with interval %s", interval)
	go func(q <-chan struct{}) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		failCount := 0
		const maxFails = 3
		for {
			select {
			case <-q:
				log.Println("[HealthCheck] Stopped")
				return
			case <-ticker.C:
				if !x.isXrayRunning.Load() || !x.isTun2socksRunning.Load() {
					return
				}
				socksAddress, _ := x.xraySocksAddress.Load().(string)
				if socksAddress == "" {
					failCount++
					log.Printf("[HealthCheck] SOCKS5 probe skipped: session address is empty (%d/%d)", failCount, maxFails)
					if failCount >= maxFails {
						log.Printf("[HealthCheck] Tunnel appears dead after %d failures", maxFails)
						x.emitStatus(EngineError, "Tunnel health check failed: SOCKS5 session address missing")
						return
					}
					continue
				}
				conn, err := net.DialTimeout("tcp", socksAddress, 2*time.Second)
				if err != nil {
					failCount++
					log.Printf("[HealthCheck] SOCKS5 probe failed (%d/%d): %v", failCount, maxFails, err)
					if failCount >= maxFails {
						log.Printf("[HealthCheck] Tunnel appears dead after %d failures", maxFails)
						x.emitStatus(EngineError, "Tunnel health check failed: SOCKS5 unreachable")
						return
					}
				} else {
					conn.Close()
					if failCount > 0 {
						log.Printf("[HealthCheck] SOCKS5 probe recovered after %d failures", failCount)
					}
					failCount = 0
				}
			}
		}
	}(quit)
}

func (x *CoreController) stopHealthCheck() {
	if x.healthCheckQuit != nil {
		select {
		case <-x.healthCheckQuit:
		default:
			close(x.healthCheckQuit)
		}
		x.healthCheckQuit = nil
	}
}
