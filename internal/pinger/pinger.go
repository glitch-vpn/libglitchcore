// Package pinger measures per-link url-test latency, and dials through one link,
// without a running engine or TUN.
package pinger

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

const (
	defaultProbeURL    = "https://www.gstatic.com/generate_204"
	defaultTimeoutMs   = 5000
	defaultConcurrency = 8

	// Probe this many times on a keep-alive transport and report the min: the
	// first sample pays the handshake, later ones reuse the warm transport.
	probeSamples = 3
)

// Engine, when set, is the engine the caller pinned ("xray" or "mihomo"): every
// link is measured on it alone, and a link it cannot carry is reported
// unreachable, never on another engine. Empty keeps the per-link choice.
type Request struct {
	Engine      string   `json:"engine,omitempty"`
	Links       []string `json:"links"`
	ProbeURL    string   `json:"probeUrl"`
	TimeoutMs   int      `json:"timeoutMs"`
	Concurrency int      `json:"concurrency"`
}

type Result struct {
	Index   int    `json:"index"`
	Engine  string `json:"engine"`
	Alive   bool   `json:"alive"`
	DelayMs int64  `json:"delayMs"`
	Error   string `json:"error,omitempty"`
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// dialOpener starts what a dial through one link needs and returns the dial
// with the call that ends it. resolveAtDial leaves the server's name for each
// dial to resolve, where an engine would otherwise resolve it once on opening;
// mihomo always does.
type dialOpener func(link string, resolveAtDial bool) (dial dialFunc, release func(), err error)

type linkEngine struct {
	engine string
	match  func(trimmed, lower string) bool
	open   dialOpener
}

// Specific engines first; mihomo fallback covers the rest (or all, without xray).
var (
	linkEngines []linkEngine
	fallback    *linkEngine
)

func registerLinkEngine(e linkEngine) { linkEngines = append(linkEngines, e) }

func setFallbackLinkEngine(e linkEngine) { fallback = &e }

// fallsBack marks an engine's refusal of a link for something it lacks, not for
// the link's safety: the fallback engine may carry it intact.
type fallsBack struct{ error }

func (e fallsBack) Unwrap() error { return e.error }

func lookup(link string) *linkEngine {
	trimmed := strings.TrimSpace(link)
	lower := strings.ToLower(trimmed)
	for i := range linkEngines {
		if linkEngines[i].match(trimmed, lower) {
			return &linkEngines[i]
		}
	}
	if fallback != nil && fallback.match(trimmed, lower) {
		return fallback
	}
	return nil
}

// lookupOn is lookup for a pinned engine: that engine if it carries the link,
// else none. Never a fallback to another engine.
func lookupOn(pinned, link string) *linkEngine {
	trimmed := strings.TrimSpace(link)
	lower := strings.ToLower(trimmed)
	for i := range linkEngines {
		if linkEngines[i].engine == pinned {
			if linkEngines[i].match(trimmed, lower) {
				return &linkEngines[i]
			}
			return nil
		}
	}
	if fallback != nil && fallback.engine == pinned && fallback.match(trimmed, lower) {
		return fallback
	}
	return nil
}

var (
	errUnsupportedLink = errors.New("unsupported link scheme")
	errNotCarried      = errors.New("link not carried by the pinned engine")
)

// dialFor opens a dial through link on the pinned engine alone, or on the
// link's own with the fallback for a capability it lacks. The engine's name
// comes back with a refusal too.
func dialFor(pinned, link string, resolveAtDial bool) (engine string, dial dialFunc, release func(), err error) {
	pinned = strings.TrimSpace(pinned)
	var chosen *linkEngine
	if pinned != "" {
		if chosen = lookupOn(pinned, link); chosen == nil {
			return pinned, nil, nil, errNotCarried
		}
	} else if chosen = lookup(link); chosen == nil {
		return "", nil, nil, errUnsupportedLink
	}

	dial, release, err = chosen.open(link, resolveAtDial)
	var refused fallsBack
	if trimmed := strings.TrimSpace(link); errors.As(err, &refused) && pinned == "" && fallback != nil &&
		fallback.match(trimmed, strings.ToLower(trimmed)) {
		chosen = fallback
		dial, release, err = chosen.open(link, resolveAtDial)
	}
	return chosen.engine, dial, release, err
}

// Dialer dials through one link until Release, with no listener, session or TUN.
type Dialer struct {
	// Engine is "xray" or "mihomo".
	Engine  string
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Release func()
}

// NewDialer is for a dial that stays open: it resolves the server's name at each
// dial, not once, since the address it got at the start can stop being that
// server's (a tunnel's fake-ip pool restarts).
func NewDialer(pinned, link string) (*Dialer, error) {
	engine, dial, release, err := dialFor(pinned, link, true)
	if err != nil {
		return nil, err
	}
	return &Dialer{Engine: engine, Dial: dial, Release: release}, nil
}

// Measure: results are index-aligned; a dead link sets Alive=false, doesn't fail the batch.
func Measure(req Request) []Result {
	probeURL := strings.TrimSpace(req.ProbeURL)
	if probeURL == "" {
		probeURL = defaultProbeURL
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if req.TimeoutMs <= 0 {
		timeout = defaultTimeoutMs * time.Millisecond
	}
	concurrency := req.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	results := make([]Result, len(req.Links))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, link := range req.Links {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, link string) {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			engine, dial, release, err := dialFor(req.Engine, link, false)
			results[i] = Result{Index: i, Engine: engine}
			var delay time.Duration
			if err == nil {
				defer release()
				delay, err = probe(ctx, probeURL, dial)
			}
			if err != nil {
				// A parse error quotes the link it rejected.
				results[i].Error = logfmt.Scrub(err.Error())
				return
			}
			results[i].Alive = true
			results[i].DelayMs = delay.Milliseconds()
		}(i, link)
	}

	wg.Wait()
	return results
}

func probe(ctx context.Context, probeURL string, dial dialFunc) (time.Duration, error) {
	transport := &http.Transport{DialContext: dial}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}

	sample := func() (time.Duration, error) {
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

	best := time.Duration(0)
	got := false
	var lastErr error
	for i := 0; i < probeSamples; i++ {
		d, err := sample()
		if err != nil {
			lastErr = err
			continue
		}
		if !got || d < best {
			best, got = d, true
		}
	}
	if !got {
		return 0, lastErr
	}
	return best, nil
}
