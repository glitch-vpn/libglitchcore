//go:build !no_xray

package core

import (
	"fmt"
	"strings"

	"github.com/glitch-vpn/libglitchcore/internal/serverinfo"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
	xrayStats "github.com/xtls/xray-core/features/stats"
)

const (
	// One observatory probe is a TLS handshake plus a 204 fetch (a few KiB) and
	// it touches every subject tag, so a winner must clear this floor and lead
	// the runner-up to count as the outbound in use.
	minTagTrafficDelta = 32 * 1024
	tagTrafficLead     = 2
)

// leastping is followed by traffic; random/roundrobin dispatch per connection,
// so their Selected stays nil.
func (x *CoreController) initXrayServerState(res *xrayconfig.BuildResult, links []string, o engineOpts) {
	servers := serverinfo.FromLinks(links)
	if len(servers) == 0 || len(servers) != len(res.OutboundTags) {
		return
	}
	sel := serverinfo.Selection{Engine: "xray", Total: len(servers), Servers: servers}
	if !res.RouteIsBalancer {
		s := servers[0]
		sel.Selected = &s
		x.setServerSelection(&sel)
		return
	}

	strat := strings.ToLower(strings.TrimSpace(o.strategy))
	if strat == "" {
		strat = xrayconfig.StrategyLeastPing
	}
	sel.Strategy = strat
	if strat == xrayconfig.StrategyLeastPing {
		// Until traffic identifies an outbound, the balancer routes through its
		// fallback tag - the first one.
		s := servers[0]
		sel.Selected = &s
	}
	x.setServerSelection(&sel)

	if strat != xrayconfig.StrategyLeastPing {
		return
	}
	base := sel
	base.Selected = nil
	// The manager is captured, not re-read: its counters are atomics, so the
	// poller needs no lock, and taking coreMutex here could deadlock a stop.
	x.startSelectionWatch(base, tagTrafficPicker(x.xrayStatsManager, res.OutboundTags))
}

// tagTrafficPicker: the outbound whose byte counters grew most since the last
// poll, -1 while no tag stands out. Observatory probes spread evenly over the
// tags, while the liveness probe and the external-IP fetch ride the outbound
// actually in use, so it leads even on an otherwise idle tunnel.
//
// xray's own observatory report is not consulted: GetObservation reads the
// observer's status slice without its lock (xray-core v26.10.21,
// app/observatory/observer.go:41), and polling that from here made the race
// deterministic.
func tagTrafficPicker(mgr xrayStats.Manager, tags []string) func() int {
	return tagTrafficPickerFrom(xrayStatsSource{mgr}, tags)
}

// The picker reads counters through this narrow view so it is testable without
// a live core.
type statsCounter interface{ Value() int64 }

type statsSource interface {
	GetCounter(name string) statsCounter
}

type xrayStatsSource struct{ mgr xrayStats.Manager }

func (s xrayStatsSource) GetCounter(name string) statsCounter {
	if s.mgr == nil {
		return nil
	}
	if c := s.mgr.GetCounter(name); c != nil {
		return c
	}
	return nil
}

func tagTrafficPickerFrom(src statsSource, tags []string) func() int {
	prev := make([]uint64, len(tags))
	seeded := false
	return func() int {
		cur := tagTraffic(src, tags)
		if !seeded {
			copy(prev, cur)
			seeded = true
			return -1
		}
		best, bestDelta, runnerUp := -1, uint64(0), uint64(0)
		for i := range tags {
			var delta uint64
			if cur[i] >= prev[i] {
				delta = cur[i] - prev[i]
			}
			switch {
			case delta > bestDelta:
				best, runnerUp, bestDelta = i, bestDelta, delta
			case delta > runnerUp:
				runnerUp = delta
			}
		}
		copy(prev, cur)
		if bestDelta < minTagTrafficDelta || bestDelta < runnerUp*tagTrafficLead {
			return -1
		}
		return best
	}
}

func tagTraffic(src statsSource, tags []string) []uint64 {
	out := make([]uint64, len(tags))
	if src == nil {
		return out
	}
	for i, tag := range tags {
		for _, dir := range [...]string{"uplink", "downlink"} {
			if c := src.GetCounter(fmt.Sprintf("outbound>>>%s>>>traffic>>>%s", tag, dir)); c != nil {
				out[i] += uint64(c.Value())
			}
		}
	}
	return out
}
