//go:build !no_xray || (!no_mihomo && !no_awg)

package core

import (
	"sync"
	"testing"

	tun2socksLog "github.com/xjasonlyu/tun2socks/v2/log"
	"go.uber.org/zap"
	glog "gvisor.dev/gvisor/pkg/log"
)

// gVisor's stack logs from its own goroutines while a start swaps the logger;
// the race detector is the assertion.
func TestTun2socksSink_SwapRacesNoStackLogging(t *testing.T) {
	captureLogs(t, 2)
	t.Cleanup(func() { tun2socksLog.SetLogger(zap.NewNop()) })
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					glog.Warningf("x %d", 1)
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		useTun2socksSink("warn")
	}
	close(stop)
	wg.Wait()
}
