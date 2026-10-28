//go:build !no_mihomo

package core

import (
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/tunnel/statistic"
)

func TestMihomoTraffic_NeverStepsBack(t *testing.T) {
	var traffic mihomoTraffic
	traffic.startSession()
	_, baseDown := statistic.DefaultManager.Total()

	statistic.DefaultManager.PushDownloaded(100)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, down := statistic.DefaultManager.Total(); down >= baseDown+100 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("manager did not count the pushed bytes")
		}
		time.Sleep(5 * time.Millisecond)
	}
	rx, _ := traffic.proxied()
	if rx != 100 {
		t.Fatalf("rx = %d, want 100", rx)
	}

	// A DIRECT chunk is counted when read, before the manager's total has it.
	traffic.directDown.Add(60)
	if got, _ := traffic.proxied(); got != 100 {
		t.Fatalf("rx stepped to %d, want it held at 100", got)
	}
	statistic.DefaultManager.PushDownloaded(60)
	time.Sleep(50 * time.Millisecond)
	if got, _ := traffic.proxied(); got < 100 {
		t.Fatalf("rx = %d, stepped back", got)
	}

	traffic.startSession()
	if got, _ := traffic.proxied(); got != 0 {
		t.Fatalf("rx after a new session = %d, want 0", got)
	}
}

// A read and a session start run on different goroutines: the status poll and
// the engine start. The race detector is the assertion.
func TestMihomoTraffic_StartSessionAndReadDoNotRace(t *testing.T) {
	var traffic mihomoTraffic
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 500 {
			traffic.startSession()
		}
	}()
	go func() {
		defer wg.Done()
		for range 500 {
			traffic.proxied()
		}
	}()
	wg.Wait()
}
