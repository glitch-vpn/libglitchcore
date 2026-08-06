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
