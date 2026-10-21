package core

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	xproxy "golang.org/x/net/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/liveness"
	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

const (
	defaultLivenessProbeURL = "https://www.gstatic.com/generate_204"
	defaultLivenessInterval = 20 * time.Second
	// quickLivenessInterval polls faster while not up, to confirm an outage or
	// recovery without waiting the full interval.
	quickLivenessInterval = 5 * time.Second
	livenessProbeTimeout  = 8 * time.Second
)

// livenessParams: exactly one of probe/passive is set. probe actively fetches
// through the tunnel; passive samples WireGuard counters on Android, where our
// own package is excluded from the VPN and can't route into it.
type livenessParams struct {
	engine   string
	interval time.Duration
	probe    func(ctx context.Context) (time.Duration, error)
	passive  func() (liveness.WGSample, error)
}

func livenessInterval(sec int) time.Duration {
	if sec >= 10 && sec <= 300 {
		return time.Duration(sec) * time.Second
	}
	return defaultLivenessInterval
}

func (x *CoreController) startLiveness(p livenessParams) {
	x.stopLiveness()
	if p.probe == nil && p.passive == nil {
		return
	}
	if p.interval <= 0 {
		p.interval = defaultLivenessInterval
	}
	x.linkState.Store(int32(liveness.StateUnknown))
	x.linkProbeMs.Store(-1)

	quit := make(chan struct{})
	done := make(chan struct{})
	x.loopsMu.Lock()
	x.livenessQuit, x.livenessDone = quit, done
	x.loopsMu.Unlock()
	log.Printf("[liveness] started for %s (interval %s)", p.engine, p.interval)

	go func() {
		defer close(done)
		var tr liveness.Tracker
		timer := time.NewTimer(quickLivenessInterval)
		defer timer.Stop()
		for {
			select {
			case <-quit:
				return
			case <-timer.C:
			}

			if p.probe != nil {
				ctx, cancel := context.WithTimeout(context.Background(), livenessProbeTimeout)
				elapsed, err := p.probe(ctx)
				cancel()
				if err != nil {
					if _, changed := tr.ObserveFailure(); changed {
						logfmt.Warnf("[liveness] %s: internet through tunnel is DOWN: %v", p.engine, err)
					}
				} else {
					x.linkProbeMs.Store(elapsed.Milliseconds())
					if _, changed := tr.ObserveSuccess(); changed {
						log.Printf("[liveness] %s: internet through tunnel is up (%dms)", p.engine, elapsed.Milliseconds())
						// The exit IP may (re)appear or change on recovery.
						x.triggerIPResolve("link-up")
					}
				}
			} else {
				sample, err := p.passive()
				if err != nil {
					// Can't read counters (engine tearing down) - not a link verdict.
					select {
					case <-quit:
						return
					default:
					}
					logfmt.Warnf("[liveness] %s: passive sample failed: %v", p.engine, err)
				} else if st, changed := tr.ObserveWG(sample); changed {
					log.Printf("[liveness] %s: internet through tunnel is %s (passive wg)", p.engine, st)
					if st == liveness.StateUp {
						x.triggerIPResolve("link-up (passive)")
					}
				}
			}
			if s := tr.State(); s != liveness.StateUnknown {
				x.linkState.Store(int32(s))
			}

			next := p.interval
			if tr.State() != liveness.StateUp {
				next = quickLivenessInterval
			}
			timer.Reset(next)
		}
	}()
}

// Pointers swap out under the lock, close and wait happen outside it: the
// passive sampler takes coreMutex, so holding a lock across the wait would
// deadlock a stop, and a second concurrent stop must find nil rather than
// double-close quit.
func (x *CoreController) stopLiveness() {
	x.loopsMu.Lock()
	quit, done := x.livenessQuit, x.livenessDone
	x.livenessQuit, x.livenessDone = nil, nil
	x.loopsMu.Unlock()
	if quit == nil {
		return
	}
	close(quit)
	if done != nil {
		<-done
	}
	x.linkState.Store(int32(liveness.StateUnknown))
	x.linkProbeMs.Store(-1)
}

// livenessSnapshot: known=false until the first conclusive observation.
func (x *CoreController) livenessSnapshot() (up bool, probeMs int64, known bool) {
	st := liveness.State(x.linkState.Load())
	if st == liveness.StateUnknown {
		return false, -1, false
	}
	return st == liveness.StateUp, x.linkProbeMs.Load(), true
}

// Any HTTP response = end-to-end connectivity; keep-alive off so each probe re-dials.
func probeOnce(ctx context.Context, probeURL string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (time.Duration, error) {
	tr := &http.Transport{DialContext: dial, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(start)
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	return elapsed, nil
}

func loopbackSocksURL(hostPort, user, pass string) string {
	u := url.URL{Scheme: "socks5", Host: hostPort}
	if user != "" && pass != "" {
		u.User = url.UserPassword(user, pass)
	}
	return u.String()
}

// socksContextDialer dials TCP through the loopback SOCKS inbound (the same
// path as user traffic after tun2socks), so connections traverse the tunnel
// even on Android, where our own sockets bypass the VPN.
func socksContextDialer(socksURL string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	u, err := url.Parse(socksURL)
	if err != nil {
		return nil, fmt.Errorf("socks url: %w", err)
	}
	var auth *xproxy.Auth
	if u.User != nil {
		pass, _ := u.User.Password()
		auth = &xproxy.Auth{User: u.User.Username(), Password: pass}
	}
	d, err := xproxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: livenessProbeTimeout})
	if err != nil {
		return nil, fmt.Errorf("socks dialer: %w", err)
	}
	cd, ok := d.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("socks dialer has no DialContext")
	}
	return cd.DialContext, nil
}

// Built per call - the inbound may not be accepting yet when the session is
// configured.
func socksTunnelDial(socksURL string) tunnelDialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d, err := socksContextDialer(socksURL)
		if err != nil {
			return nil, err
		}
		return d(ctx, network, addr)
	}
}

func socksProber(socksURL, probeURL string) func(ctx context.Context) (time.Duration, error) {
	return tunnelProber(socksTunnelDial(socksURL), probeURL)
}

func tunnelProber(dial tunnelDialFunc, probeURL string) func(ctx context.Context) (time.Duration, error) {
	if probeURL == "" {
		probeURL = defaultLivenessProbeURL
	}
	return func(ctx context.Context) (time.Duration, error) {
		return probeOnce(ctx, probeURL, dial)
	}
}

// directProber uses the OS default route - on desktop it goes into the TUN, so
// the probe traverses the awg tunnel end-to-end.
func directProber(probeURL string) func(ctx context.Context) (time.Duration, error) {
	if probeURL == "" {
		probeURL = defaultLivenessProbeURL
	}
	dialer := &net.Dialer{Timeout: livenessProbeTimeout}
	return func(ctx context.Context) (time.Duration, error) {
		return probeOnce(ctx, probeURL, dialer.DialContext)
	}
}
