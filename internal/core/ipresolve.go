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
	ipFetchTimeout     = 12 * time.Second
)

type tunnelDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Fixed for one engine session. dial must route through the tunnel.
type ipResolveConfig struct {
	enabled bool
	urlV4   string
	urlV6   string
	skipV6  bool // disableIPv6 requested - don't even try
	// localNetworksDirect: the private ranges leave the tunnel, so an IPv6 flow
	// to a unique local address never meets the exit.
	localNetworksDirect bool
	dial                tunnelDialFunc
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
	x.ipResolve.Store(cfg)
	x.settleExitIPv6Locked(cfg)
	x.ipFetchMu.Unlock()
}

func (x *CoreController) stopIPResolve() {
	setSingTunAdmission(nil)
	x.ipFetchMu.Lock()
	x.ipGen.Add(1)
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
	x.ipFetchMu.Unlock()
	log.Printf("[ipresolve] external IP fetch scheduled (%s)", reason)

	go func() {
		for {
			cfg, _ := x.ipResolve.Load().(ipResolveConfig)
			gen := x.ipGen.Load()
			if cfg.enabled {
				x.setExternalIPState(gen, fetchExternalIPs(cfg, x.knownIPv6State(), func(outcome echoV6Outcome) { x.echoFinishedV6(gen, outcome) }))
			}
			x.ipFetchMu.Lock()
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
		ip, err := fetchIPEchoOnce(cfg.urlV4, cfg.dial, false)
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
			ip, err := fetchIPEchoOnce(cfg.urlV6, cfg.dial, true)
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

// One attempt: an exit without IPv6 answers it with a failure, and that failure
// is the answer. The engine's own dial may still try each address the name
// resolves to.
func fetchIPEchoOnce(echoURL string, dial tunnelDialFunc, wantV6 bool) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ipFetchTimeout)
	defer cancel()
	return fetchIPEcho(ctx, echoURL, dial, wantV6)
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
