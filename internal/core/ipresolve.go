package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

// Family-specific echo hosts: api.ipify.org has only an A record and
// api6.ipify.org only AAAA, so each fetch pins its address family end-to-end
// even when the exit resolves the name.
const (
	defaultIPv4EchoURL = "https://api.ipify.org"
	defaultIPv6EchoURL = "https://api6.ipify.org"
)

// echoRoundBudget is how long one echo round may take, a failed lookup's
// retries included.
var echoRoundBudget = 12 * time.Second

type tunnelDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Fixed for one engine session. dial must route through the tunnel.
type ipResolveConfig struct {
	enabled bool
	urlV4   string
	urlV6   string
	skipV6  bool // disableIPv6 requested - don't even try
	// ctx ends with the session; an echo in flight ends with it. Nil is a
	// context that never ends.
	ctx context.Context
	// localNetworksDirect: the private ranges leave the tunnel, so an IPv6 flow
	// to a unique local address never meets the exit.
	localNetworksDirect bool
	dial                tunnelDialFunc
}

func (c ipResolveConfig) context() context.Context {
	if c.ctx == nil {
		return context.Background()
	}
	return c.ctx
}

// IPEvent payload. A missing address always comes with its error ("disabled" or
// the fetch failure).
type externalIPState struct {
	IPv4      string `json:"ipv4,omitempty"`
	IPv6      string `json:"ipv6,omitempty"`
	IPv4Error string `json:"ipv4Error,omitempty"`
	IPv6Error string `json:"ipv6Error,omitempty"`
}

// Arms only - fetches are kicked by triggerIPResolve on link-up.
func (x *CoreController) configureIPResolve(cfg ipResolveConfig) {
	setSingTunAdmission(x.admitTCPFlow)
	if cfg.urlV4 == "" {
		cfg.urlV4 = defaultIPv4EchoURL
	}
	if cfg.urlV6 == "" {
		cfg.urlV6 = defaultIPv6EchoURL
	}
	x.ipFetchMu.Lock()
	x.ipGen.Add(1)
	x.ipStateJSON.Store("")
	if x.ipResolveCancel != nil {
		x.ipResolveCancel()
	}
	cfg.ctx, x.ipResolveCancel = context.WithCancel(context.Background())
	x.ipResolve.Store(cfg)
	x.settleExitIPv6Locked(cfg)
	x.ipFetchMu.Unlock()
}

func (x *CoreController) stopIPResolve() {
	setSingTunAdmission(nil)
	x.ipFetchMu.Lock()
	x.ipGen.Add(1)
	if x.ipResolveCancel != nil {
		x.ipResolveCancel()
		x.ipResolveCancel = nil
	}
	// The round in flight ends on its own; the next session's first round does
	// not queue behind it.
	x.ipFetchLoop++
	x.ipFetchBusy, x.ipFetchAgain = false, false
	x.ipResolve.Store(ipResolveConfig{})
	x.ipStateJSON.Store("")
	x.exitPerConnection.Store(false)
	x.storeExitIPv6Locked(exitIPv6Unknown)
	x.ipFetchMu.Unlock()
}

// The generation is re-checked under the lock that stops bump it with, so a
// fetch that finished after a stop cannot store or emit a stale address.
func (x *CoreController) setExternalIPState(gen int64, st externalIPState) {
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	msg := string(b)
	x.ipFetchMu.Lock()
	stale := x.ipGen.Load() != gen
	prev, _ := x.ipStateJSON.Load().(string)
	if !stale && prev != msg {
		x.ipStateJSON.Store(msg)
	}
	x.ipFetchMu.Unlock()
	if stale || prev == msg {
		return
	}
	x.emitStatus(IPEvent, msg)
}

// A trigger during an in-flight fetch queues exactly one follow-up;
// config/generation are re-read per round, so a queued round after an engine
// restart uses the new session's settings.
func (x *CoreController) triggerIPResolve(reason string) {
	cfg, _ := x.ipResolve.Load().(ipResolveConfig)
	if !cfg.enabled {
		return
	}
	x.ipFetchMu.Lock()
	if x.ipFetchBusy {
		x.ipFetchAgain = true
		x.ipFetchMu.Unlock()
		return
	}
	x.ipFetchBusy = true
	x.ipFetchLoop++
	loop := x.ipFetchLoop
	x.ipFetchMu.Unlock()
	log.Printf("[ipresolve] external IP fetch scheduled (%s)", reason)

	go func() {
		for {
			cfg, _ := x.ipResolve.Load().(ipResolveConfig)
			gen := x.ipGen.Load()
			if cfg.enabled {
				x.echoRoundStarting(gen)
				x.setExternalIPState(gen, fetchExternalIPs(cfg, x.knownIPv6State(), func(outcome echoV6Outcome) { x.echoFinishedV6(gen, outcome) }))
			}
			x.ipFetchMu.Lock()
			if x.ipFetchLoop != loop {
				x.ipFetchMu.Unlock()
				return
			}
			if !x.ipFetchAgain {
				x.ipFetchBusy = false
				x.ipFetchMu.Unlock()
				return
			}
			x.ipFetchAgain = false
			x.ipFetchMu.Unlock()
		}
	}()
}

// answeredV6, when set, is the IPv6 outcome this session already has for its
// exit: it is carried over rather than asked for again. v6Finished is called
// once with how the IPv6 echo ended: at once when it reached its host, and
// when it failed on the way only after the IPv4 echo has ended, since it is the
// IPv4 echo that tells a family without IPv6 from a tunnel that carries
// nothing.
func fetchExternalIPs(cfg ipResolveConfig, answeredV6 *externalIPState, v6Finished func(outcome echoV6Outcome)) externalIPState {
	var st externalIPState
	var wg sync.WaitGroup
	wg.Add(1)
	v4Ended := make(chan struct{})
	var v4ReachedHost bool
	go func() {
		defer wg.Done()
		defer close(v4Ended)
		ip, err := fetchIPEchoRetrying(cfg.context(), cfg.urlV4, cfg.dial, false)
		if err != nil {
			st.IPv4Error = logfmt.Scrub(err.Error())
		} else {
			st.IPv4 = ip
		}
		v4ReachedHost = reachedHost(err)
	}()
	if cfg.skipV6 {
		st.IPv6Error = "disabled"
	} else if answeredV6 != nil {
		st.IPv6, st.IPv6Error = answeredV6.IPv6, answeredV6.IPv6Error
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, err := fetchIPEchoRetrying(cfg.context(), cfg.urlV6, cfg.dial, true)
			if err != nil {
				st.IPv6Error = logfmt.Scrub(err.Error())
			} else {
				st.IPv6 = ip
			}
			if v6Finished == nil {
				return
			}
			if reachedHost(err) {
				v6Finished(echoV6Carried)
				return
			}
			if isResolutionFailure(err) {
				v6Finished(echoV6Unresolved)
				return
			}
			<-v4Ended
			if v4ReachedHost {
				v6Finished(echoV6Unreachable)
			} else {
				v6Finished(echoV6Inconclusive)
			}
		}()
	}
	wg.Wait()
	return st
}

// reachedHost reports whether an echo got an answer from its host, whatever the
// answer said.
func reachedHost(err error) bool {
	return err == nil || errors.As(err, new(*echoAnsweredError))
}

// echoAnsweredError is an echo that reached its host and got no address back.
type echoAnsweredError struct{ error }

func (e *echoAnsweredError) Unwrap() error { return e.error }

// echoResolveRetryDelay is the wait before an echo's first retry after its host
// failed to resolve; each retry waits twice as long as the one before.
var echoResolveRetryDelay = time.Second

// resolutionFailureKinds are the engines' own errors for a name that gave no
// address, each registered by the file that links the engine.
var resolutionFailureKinds []func(error) bool

// isResolutionFailure reports whether an echo failed before it had an address
// to dial, so that nothing says whether the exit carries the family.
func isResolutionFailure(err error) bool {
	if errors.As(err, new(*net.DNSError)) {
		return true
	}
	for _, kind := range resolutionFailureKinds {
		if kind(err) {
			return true
		}
	}
	return false
}

// fetchIPEchoRetrying asks one echo host. An exit without IPv6 answers with a
// failure, and that failure is the answer: the engine's dial tries each address
// the name resolves to, once. A name that gave no address, though, is no answer:
// no request left. mihomo's resolver returns an empty list without an error when
// the A lookup fails and the AAAA one is not in within 100 ms, which the dial
// reports as "no ip address", so a slow or briefly failing lookup shows up this
// way. The lookup is asked again after echoResolveRetryDelay, doubling, until
// the round's echoRoundBudget is spent or the session ends.
func fetchIPEchoRetrying(session context.Context, echoURL string, dial tunnelDialFunc, wantV6 bool) (string, error) {
	ctx, cancel := context.WithTimeout(session, echoRoundBudget)
	defer cancel()
	delay := echoResolveRetryDelay
	var unresolved error
	for {
		ip, err := fetchIPEcho(ctx, echoURL, dial, wantV6)
		if err == nil {
			return ip, nil
		}
		if !isResolutionFailure(err) {
			// A lookup that outlasted the round, or the session, is still no answer
			// from the exit.
			if unresolved != nil && ctx.Err() != nil {
				return "", unresolved
			}
			return ip, err
		}
		unresolved = err
		select {
		case <-ctx.Done():
			return "", err
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// The answer's family is validated so a mis-set echo URL can't report an
// address of the wrong family.
func fetchIPEcho(ctx context.Context, echoURL string, dial tunnelDialFunc, wantV6 bool) (string, error) {
	tr := &http.Transport{DialContext: dial, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, echoURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	// From here the host answered, whatever it says.
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return "", &echoAnsweredError{fmt.Errorf("echo status %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(body))
	ip := net.ParseIP(s)
	if ip == nil {
		if len(s) > 64 {
			s = s[:64]
		}
		return "", &echoAnsweredError{fmt.Errorf("echo returned %q", s)}
	}
	if isV4 := ip.To4() != nil; isV4 == wantV6 {
		return "", &echoAnsweredError{fmt.Errorf("echo returned wrong family: %s", ip)}
	}
	return ip.String(), nil
}
