// Package pinger measures per-link url-test latency without a running engine or TUN.
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

// Engine, when set, is the engine the caller pinned ("xray", "mihomo" or
// "awg"): every link is measured on it alone, and a link it cannot carry is
// reported unreachable, never on another engine. Empty keeps the per-link choice.
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

type measurer func(ctx context.Context, link, probeURL string) (time.Duration, error)

type engineMeasurer struct {
	engine  string
	match   func(trimmed, lower string) bool
	measure measurer
}

// Specific measurers first; mihomo fallback covers the rest (or all, without xray).
var (
	measurers []engineMeasurer
	fallback  *engineMeasurer
)

func registerMeasurer(m engineMeasurer) { measurers = append(measurers, m) }

func setFallbackMeasurer(m engineMeasurer) { fallback = &m }

// fallsBack marks a measurer's refusal of a link for something the engine
// lacks, not for the link's safety: the fallback engine may carry it intact.
type fallsBack struct{ error }

func (e fallsBack) Unwrap() error { return e.error }

func matchAwgLink(trimmed, lower string) bool {
	return strings.HasPrefix(lower, "awg://") || strings.Contains(trimmed, "[Interface]")
}

func classify(link string) (engine string, m measurer) {
	trimmed := strings.TrimSpace(link)
	lower := strings.ToLower(trimmed)
	for _, em := range measurers {
		if em.match(trimmed, lower) {
			return em.engine, em.measure
		}
	}
	if fallback != nil && fallback.match(trimmed, lower) {
		return fallback.engine, fallback.measure
	}
	return "", nil
}

// classifyOn is classify for a pinned engine: the measurer of that engine if it
// carries the link, else none. Never a fallback to another engine.
func classifyOn(pinned, link string) (engine string, m measurer, ok bool) {
	trimmed := strings.TrimSpace(link)
	lower := strings.ToLower(trimmed)
	for _, em := range measurers {
		if em.engine == pinned {
			if em.match(trimmed, lower) {
				return em.engine, em.measure, true
			}
			return pinned, nil, false
		}
	}
	// The awg engine carries awg links only, so the fallback engine's measurer
	// is not offered one.
	if fallback != nil && fallback.engine == pinned && !matchAwgLink(trimmed, lower) &&
		fallback.match(trimmed, lower) {
		return fallback.engine, fallback.measure, true
	}
	return pinned, nil, false
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
		var engine string
		var m measurer
		if pinned := strings.TrimSpace(req.Engine); pinned != "" {
			engine, m, _ = classifyOn(pinned, link)
			results[i] = Result{Index: i, Engine: engine}
			if m == nil {
				results[i].Error = "link not carried by the pinned engine"
				continue
			}
		} else {
			engine, m = classify(link)
			results[i] = Result{Index: i, Engine: engine}
			if m == nil {
				results[i].Error = "unsupported link scheme"
				continue
			}
		}
		pinnedRun := strings.TrimSpace(req.Engine) != ""

		wg.Add(1)
		sem <- struct{}{}
		go func(i int, link string, m measurer, pinnedRun bool) {
			defer wg.Done()
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			delay, err := m(ctx, link, probeURL)
			var refused fallsBack
			if trimmed := strings.TrimSpace(link); errors.As(err, &refused) && !pinnedRun && fallback != nil &&
				fallback.match(trimmed, strings.ToLower(trimmed)) {
				results[i].Engine = fallback.engine
				delay, err = fallback.measure(ctx, link, probeURL)
			}
			if err != nil {
				// A parse error quotes the link it rejected.
				results[i].Error = logfmt.Scrub(err.Error())
				return
			}
			results[i].Alive = true
			results[i].DelayMs = delay.Milliseconds()
		}(i, link, m, pinnedRun)
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
