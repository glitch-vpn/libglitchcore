package core

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProbeOnce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	dialer := &net.Dialer{Timeout: time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	elapsed, err := probeOnce(ctx, srv.URL, dialer.DialContext)
	if err != nil {
		t.Fatalf("probeOnce(live): %v", err)
	}
	// Not "> 0": a loopback round trip can land inside one tick of Windows'
	// coarse timer and measure exactly zero.
	if elapsed < 0 || elapsed > 3*time.Second {
		t.Fatalf("elapsed = %v, want a sane probe duration", elapsed)
	}

	srv.Close()
	if _, err := probeOnce(ctx, srv.URL, dialer.DialContext); err == nil {
		t.Fatal("probeOnce against a closed server must fail")
	}
}

func TestStopLiveness_CancelsTheProbeInFlight(t *testing.T) {
	prev := quickLivenessInterval
	quickLivenessInterval = 10 * time.Millisecond
	t.Cleanup(func() { quickLivenessInterval = prev })

	probing := make(chan struct{})
	x := &CoreController{}
	x.startLiveness(livenessParams{
		engine:   "test",
		interval: time.Hour,
		probe: func(ctx context.Context) (time.Duration, error) {
			close(probing)
			<-ctx.Done()
			return 0, ctx.Err()
		},
	})
	<-probing

	stopped := make(chan struct{})
	go func() {
		x.stopLiveness()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(livenessProbeTimeout / 2):
		t.Fatal("stopLiveness waited out the probe's timeout")
	}
}
