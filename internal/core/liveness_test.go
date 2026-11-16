package core

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

// The echo that tells the session whether its exit has IPv6 waits for the link
// to come up, so the first probe does not sit out the polling interval.
func TestStartLiveness_ProbesAtOnce(t *testing.T) {
	prev := quickLivenessInterval
	quickLivenessInterval = time.Hour
	t.Cleanup(func() { quickLivenessInterval = prev })

	probed := make(chan struct{}, 1)
	x := &CoreController{}
	x.startLiveness(livenessParams{
		engine:   "test",
		interval: time.Hour,
		probe: func(context.Context) (time.Duration, error) {
			select {
			case probed <- struct{}{}:
			default:
			}
			return time.Millisecond, nil
		},
	})
	t.Cleanup(x.stopLiveness)
	select {
	case <-probed:
	case <-time.After(2 * time.Second):
		t.Fatal("the first probe waited for the polling interval")
	}
}

// A probe whose engine resolves names itself may be handed an IPv6 address the
// exit cannot reach, and its failure then reads as a lost link. Until the exit's
// IPv6 is known to carry, the name goes out as an IPv4 address.
func TestIPv4UntilExitCarriesIPv6_DialsANameAtIPv4UntilTheVerdictCarries(t *testing.T) {
	resolve := func(_ context.Context, host string) (netip.Addr, error) {
		if host == "probe.example" {
			return netip.MustParseAddr("192.0.2.7"), nil
		}
		return netip.Addr{}, errors.New("no such name")
	}
	cases := []struct {
		name  string
		state int32
		addr  string
		want  string
	}{
		{"pending", exitIPv6Pending, "probe.example:443", "tcp4 192.0.2.7:443"},
		{"absent", exitIPv6Absent, "probe.example:443", "tcp4 192.0.2.7:443"},
		{"unknown", exitIPv6Unknown, "probe.example:443", "tcp4 192.0.2.7:443"},
		{"carried", exitIPv6Carried, "probe.example:443", "tcp probe.example:443"},
		{"IPv6 literal", exitIPv6Pending, "[2001:db8::1]:443", "tcp [2001:db8::1]:443"},
		{"IPv4 literal", exitIPv6Pending, "192.0.2.9:443", "tcp 192.0.2.9:443"},
	}
	for _, c := range cases {
		x := &CoreController{}
		x.exitIPv6.Store(c.state)
		var dialed string
		dial := x.ipv4UntilExitCarriesIPv6(func(_ context.Context, network, addr string) (net.Conn, error) {
			dialed = network + " " + addr
			return nil, errors.New("stop")
		}, resolve)
		_, _ = dial(context.Background(), "tcp", c.addr)
		if dialed != c.want {
			t.Errorf("%s: dialled %q, want %q", c.name, dialed, c.want)
		}
	}
}

func TestIPv4UntilExitCarriesIPv6_AFailedLookupFailsTheProbeWithoutDialling(t *testing.T) {
	x := &CoreController{}
	x.exitIPv6.Store(exitIPv6Pending)
	failed := errors.New("no ip address")
	dial := x.ipv4UntilExitCarriesIPv6(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialled a name that gave no IPv4 address")
		return nil, nil
	}, func(context.Context, string) (netip.Addr, error) { return netip.Addr{}, failed })
	if _, err := dial(context.Background(), "tcp", "probe.example:443"); !errors.Is(err, failed) {
		t.Fatalf("err = %v, want the lookup's", err)
	}
}
