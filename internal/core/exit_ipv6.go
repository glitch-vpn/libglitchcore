package core

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/liveness"
	"github.com/glitch-vpn/libglitchcore/internal/serverinfo"
)

// What the session knows about its exit's IPv6.
const (
	// exitIPv6Unknown: no echo is expected, or the exit is not one server, so
	// no IPv6 flow is judged.
	exitIPv6Unknown int32 = iota
	// exitIPv6Pending: the echo is yet to answer. It ends within
	// exitIPv6PendingTimeout whatever happens.
	exitIPv6Pending
	exitIPv6Carried
	exitIPv6Absent
)

// exitIPv6PendingTimeout bounds how long a session drops IPv6 SYNs while its
// echo has not answered. Past it the exit is unknown, which admits, and a late
// echo still records its answer.
var exitIPv6PendingTimeout = ipFetchTimeout

// echoV6Outcome is how a round's IPv6 echo ended.
type echoV6Outcome uint8

const (
	// echoV6Carried: the echo reached its host, whatever the host said.
	echoV6Carried echoV6Outcome = iota
	// echoV6Unreachable: the echo failed on the way while the round's IPv4 echo
	// reached its host.
	echoV6Unreachable
	// echoV6Inconclusive: both echoes failed on the way, which says nothing about
	// a family.
	echoV6Inconclusive
)

// tcpVerdict is what admitTCPFlow says to a TCP SYN; each TUN stack's fork has
// its own type for the same three answers.
type tcpVerdict uint8

const (
	tcpAdmit tcpVerdict = iota
	tcpReset
	tcpDrop
)

// The fake-ip pool of IPv6 addresses: a flow to one of them is for a name, and
// crosses the exit. The same range is in mihomoconfig and xrayconfig.
var (
	uniqueLocalPrefix = netip.MustParsePrefix("fc00::/7")
	fakeIPv6Pool      = netip.MustParsePrefix("fc00::/18")
)

// perExitSelection reports whether the selection names one exit at a time: a
// single server, or a group that moves to another server only when one fails
// or measures better. The other groups pick a server for each connection, so
// no echo speaks for the next flow.
func perExitSelection(sel *serverinfo.Selection) bool {
	if sel.Total <= 1 {
		return true
	}
	switch sel.Strategy {
	case "url-test", "fallback", "leastping":
		return true
	}
	return false
}

// settleExitIPv6Locked is the state a session's exit starts in: pending while
// an echo is to answer for it. The caller holds ipFetchMu.
func (x *CoreController) settleExitIPv6Locked(cfg ipResolveConfig) {
	if cfg.enabled && !cfg.skipV6 && !x.exitPerConnection.Load() {
		x.storeExitIPv6Locked(exitIPv6Pending)
		return
	}
	x.storeExitIPv6Locked(exitIPv6Unknown)
}

// storeExitIPv6Locked sets the state, and arms the deadline that ends a pending
// one. The caller holds ipFetchMu.
func (x *CoreController) storeExitIPv6Locked(state int32) {
	x.exitIPv6.Store(state)
	if x.exitIPv6Deadline != nil {
		x.exitIPv6Deadline.Stop()
		x.exitIPv6Deadline = nil
	}
	if state != exitIPv6Pending {
		return
	}
	gen := x.ipGen.Load()
	x.exitIPv6Deadline = time.AfterFunc(exitIPv6PendingTimeout, func() {
		x.ipFetchMu.Lock()
		defer x.ipFetchMu.Unlock()
		if x.ipGen.Load() == gen && x.exitIPv6.Load() == exitIPv6Pending {
			x.storeExitIPv6Locked(exitIPv6Unknown)
		}
	})
}

// endPendingExitIPv6 gives up waiting for the echo: the exit is unknown, which
// admits IPv6 flows, until a later echo says.
func (x *CoreController) endPendingExitIPv6() {
	x.ipFetchMu.Lock()
	defer x.ipFetchMu.Unlock()
	if x.exitIPv6.Load() == exitIPv6Pending {
		x.storeExitIPv6Locked(exitIPv6Unknown)
	}
}

// noteExitSelection follows the selection the session names. A different
// server, the first one a group names included, makes the exit's IPv6 unknown
// again and ends the echo round in flight, whose answer is the old exit's: a
// group's first echo may have gone through a server its health check has not
// confirmed.
func (x *CoreController) noteExitSelection(prev string, sel *serverinfo.Selection) {
	x.ipFetchMu.Lock()
	defer x.ipFetchMu.Unlock()
	x.exitPerConnection.Store(!perExitSelection(sel))
	if prev == "" {
		return
	}
	var before serverinfo.Selection
	if json.Unmarshal([]byte(prev), &before) != nil {
		return
	}
	cfg, _ := x.ipResolve.Load().(ipResolveConfig)
	switch {
	case x.exitPerConnection.Load():
		x.storeExitIPv6Locked(exitIPv6Unknown)
	case !reflect.DeepEqual(before.Selected, sel.Selected):
		x.ipGen.Add(1)
		x.settleExitIPv6Locked(cfg)
	}
}

// echoFinishedV6 takes a finished round's IPv6 echo as the exit's answer; gen is
// the generation the round began in. An echo that reached its host, whatever
// the host said, shows an exit that carries IPv6. One that failed on the way
// shows one that does not, but only while the tunnel is up and the round's IPv4
// echo got through: a tunnel that carries nothing says nothing about a family.
// A round that cannot tell ends the wait, so the exit is unknown.
func (x *CoreController) echoFinishedV6(gen int64, outcome echoV6Outcome) {
	x.ipFetchMu.Lock()
	defer x.ipFetchMu.Unlock()
	if x.ipGen.Load() != gen || x.exitPerConnection.Load() {
		return
	}
	switch {
	case outcome == echoV6Carried:
		x.storeExitIPv6Locked(exitIPv6Carried)
	case outcome == echoV6Unreachable && x.linkState.Load() == int32(liveness.StateUp):
		x.storeExitIPv6Locked(exitIPv6Absent)
	case x.exitIPv6.Load() == exitIPv6Pending:
		x.storeExitIPv6Locked(exitIPv6Unknown)
	}
}

// knownIPv6State is the IPv6 half of the last echo while it still holds for the
// session's exit, so a later round asks for IPv4 only.
func (x *CoreController) knownIPv6State() *externalIPState {
	switch x.exitIPv6.Load() {
	case exitIPv6Carried, exitIPv6Absent:
	default:
		return nil
	}
	var st externalIPState
	s, _ := x.ipStateJSON.Load().(string)
	if s == "" || json.Unmarshal([]byte(s), &st) != nil || (st.IPv6 == "" && st.IPv6Error == "") {
		return nil
	}
	return &st
}

// admitTCPFlow is asked with a TCP SYN's destination before the TUN stack
// answers it. An IPv6 flow through an exit with no IPv6 is reset, so the app's
// connect fails at once and it falls back to IPv4. While the echo has yet to
// say, it is dropped: the app's next SYN is judged again, and a site with only
// IPv6 connects once the answer is in. Addresses the exit never sees pass.
func (x *CoreController) admitTCPFlow(destination netip.AddrPort) tcpVerdict {
	addr := destination.Addr()
	if !addr.Is6() || addr.Is4In6() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() {
		return tcpAdmit
	}
	if cfg, _ := x.ipResolve.Load().(ipResolveConfig); cfg.localNetworksDirect &&
		uniqueLocalPrefix.Contains(addr) && !fakeIPv6Pool.Contains(addr) {
		return tcpAdmit
	}
	switch x.exitIPv6.Load() {
	case exitIPv6Absent:
		return tcpReset
	case exitIPv6Pending:
		return tcpDrop
	}
	return tcpAdmit
}
