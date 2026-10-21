package core

import (
	"context"
	"encoding/json"
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
	ipFetchAttempts    = 2
	ipFetchRetryDelay  = 2 * time.Second
)

type tunnelDialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Fixed for one engine session. dial must route through the tunnel; nil =
// this engine/platform has no in-tunnel HTTP path (Android awg).
type ipResolveConfig struct {
	enabled bool
	urlV4   string
	urlV6   string
	skipV6  bool // disableIPv6 requested - don't even try
	dial    tunnelDialFunc
}

// IPEvent payload. A missing address always comes with its error ("disabled",
// "unsupported", or the fetch failure).
type externalIPState struct {
	IPv4      string `json:"ipv4,omitempty"`
	IPv6      string `json:"ipv6,omitempty"`
	IPv4Error string `json:"ipv4Error,omitempty"`
	IPv6Error string `json:"ipv6Error,omitempty"`
}

// Arms only - fetches are kicked by triggerIPResolve on link-up.
func (x *CoreController) configureIPResolve(cfg ipResolveConfig) {
	if cfg.urlV4 == "" {
		cfg.urlV4 = defaultIPv4EchoURL
	}
	if cfg.urlV6 == "" {
		cfg.urlV6 = defaultIPv6EchoURL
	}
	x.ipFetchMu.Lock()
	gen := x.ipGen.Add(1)
	x.ipStateJSON.Store("")
	x.ipResolve.Store(cfg)
	x.ipFetchMu.Unlock()
	if cfg.enabled && cfg.dial == nil {
		// No way to route our own HTTP through this tunnel - say so explicitly
		// so UIs don't wait forever.
		x.setExternalIPState(gen, externalIPState{IPv4Error: "unsupported", IPv6Error: "unsupported"})
	}
}

func (x *CoreController) stopIPResolve() {
	x.ipFetchMu.Lock()
	x.ipGen.Add(1)
	x.ipResolve.Store(ipResolveConfig{})
	x.ipStateJSON.Store("")
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
	if !cfg.enabled || cfg.dial == nil {
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
			if cfg.enabled && cfg.dial != nil {
				x.setExternalIPState(gen, fetchExternalIPs(cfg))
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

func fetchExternalIPs(cfg ipResolveConfig) externalIPState {
	var st externalIPState
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if ip, err := fetchIPEchoRetry(cfg.urlV4, cfg.dial, false); err != nil {
			st.IPv4Error = logfmt.Scrub(err.Error())
		} else {
			st.IPv4 = ip
		}
	}()
	if cfg.skipV6 {
		st.IPv6Error = "disabled"
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ip, err := fetchIPEchoRetry(cfg.urlV6, cfg.dial, true); err != nil {
				st.IPv6Error = logfmt.Scrub(err.Error())
			} else {
				st.IPv6 = ip
			}
		}()
	}
	wg.Wait()
	return st
}

func fetchIPEchoRetry(echoURL string, dial tunnelDialFunc, wantV6 bool) (string, error) {
	var lastErr error
	for i := 0; i < ipFetchAttempts; i++ {
		if i > 0 {
			time.Sleep(ipFetchRetryDelay)
		}
		ctx, cancel := context.WithTimeout(context.Background(), ipFetchTimeout)
		ip, err := fetchIPEcho(ctx, echoURL, dial, wantV6)
		cancel()
		if err == nil {
			return ip, nil
		}
		lastErr = err
	}
	return "", lastErr
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
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("echo status %d", resp.StatusCode)
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
		return "", fmt.Errorf("echo returned %q", s)
	}
	if isV4 := ip.To4() != nil; isV4 == wantV6 {
		return "", fmt.Errorf("echo returned wrong family: %s", ip)
	}
	return ip.String(), nil
}
