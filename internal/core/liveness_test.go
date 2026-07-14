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
	if elapsed <= 0 {
		t.Fatalf("elapsed = %v, want > 0", elapsed)
	}

	srv.Close()
	if _, err := probeOnce(ctx, srv.URL, dialer.DialContext); err == nil {
		t.Fatal("probeOnce against a closed server must fail")
	}
}
