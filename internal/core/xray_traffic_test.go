//go:build !no_xray

package core

import (
	"context"
	"sync"
	"testing"
	"time"

	xrayStatsApp "github.com/xtls/xray-core/app/stats"
)

func TestSumOutboundTraffic_DownlinkIsRxUplinkIsTx(t *testing.T) {
	tags := []string{"proxy-0", "proxy-1"}
	src := newFakeStats(tags)
	src.counters["outbound>>>proxy-0>>>traffic>>>downlink"].Add(100)
	src.counters["outbound>>>proxy-1>>>traffic>>>downlink"].Add(20)
	src.counters["outbound>>>proxy-0>>>traffic>>>uplink"].Add(3)
	src.counters["outbound>>>proxy-1>>>traffic>>>uplink"].Add(4)

	rx, tx := sumOutboundTraffic(src, tags)
	if rx != 120 || tx != 7 {
		t.Fatalf("rx, tx = %d, %d; want 120, 7", rx, tx)
	}
}

func newXrayStatsManager(t *testing.T, tags []string, bytesPerCounter int64) *xrayStatsApp.Manager {
	t.Helper()
	mgr, err := xrayStatsApp.NewManager(context.Background(), &xrayStatsApp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range tags {
		for _, dir := range []string{"uplink", "downlink"} {
			c, err := mgr.RegisterCounter("outbound>>>" + tag + ">>>traffic>>>" + dir)
			if err != nil {
				t.Fatal(err)
			}
			c.Add(bytesPerCounter)
		}
	}
	return mgr
}

func TestXrayTraffic_ReadsWhileAStartOrStopHoldsTheCore(t *testing.T) {
	tags := []string{"proxy-0", "proxy-1"}
	x := &CoreController{}
	x.xrayTraffic.Store(&xrayTrafficSource{stats: newXrayStatsManager(t, tags, 10), tags: tags})
	x.isXrayRunning.Store(true)

	rx, tx, running := readTrafficWhileTheCoreIsHeld(t, x)
	if !running || rx != 20 || tx != 20 {
		t.Fatalf("rx, tx, running = %d, %d, %v; want 20, 20, true", rx, tx, running)
	}
}

// Run with -race: the reader and the session's end share only the snapshot.
func TestXrayTraffic_ReadsRaceASessionEnding(t *testing.T) {
	tags := []string{"proxy-0"}
	x := &CoreController{}
	var readers sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					x.readEngineTraffic()
				}
			}
		}()
	}
	for range 200 {
		x.xrayTraffic.Store(&xrayTrafficSource{stats: newXrayStatsManager(t, tags, 1), tags: tags})
		x.isXrayRunning.Store(true)
		x.coreMutex.Lock()
		x.isXrayRunning.Store(false)
		x.xrayTraffic.Store(nil)
		x.coreMutex.Unlock()
	}
	close(stop)
	readers.Wait()
}

// The plugin asks which engine runs from the UI thread, during a connect too.
func TestXrayRunning_AnswersWhileAStartHoldsTheCore(t *testing.T) {
	x := &CoreController{}
	x.xrayStarting.Store(true)
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	answered := make(chan string, 1)
	go func() { answered <- x.activeEngineID() }()
	select {
	case id := <-answered:
		if id != "xray" {
			t.Fatalf("active engine during an xray start = %q", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("asking which engine runs waited on coreMutex")
	}
}
