package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// Hotspot sharing: while a Windows hotspot runs, the shared connection (ICS)
// decides where its clients go. This file holds the order in which the shared
// connection and the forwarding block follow the tunnel; the OS calls are
// behind hotspotOS.
//
// One rule closes every gap: forwarding on the hotspot's interface is on only
// while ICS's public side is the connection the tunnel's phase wants. Anything
// else, unknown or refused or a tunnel still going away, is forwarding off.

const (
	hotspotSharedTunnel = "tunnel"
	hotspotSharedWiFi   = "wifi"
	hotspotSharedNone   = "none"
)

// Results of PrepareHotspot and SetHotspotSharing; 0 is success.
const (
	hotspotResultBadRequest   = 2
	hotspotResultUnsupported  = 3
	hotspotResultRunning      = 4
	hotspotResultNeedsAdmin   = 5
	hotspotResultRepairFailed = 6
)

// hotspotReconcileEvery is how often a running hotspot is checked against what
// it should be: ICS turns forwarding on again by itself when it resumes.
const hotspotReconcileEvery = time.Second

// maxBlockedClients bounds the per-device filters one hotspot holds.
const maxBlockedClients = 8

type hotspotSharingRequest struct {
	On                   bool     `json:"on"`
	BlockWhileTunnelDown bool     `json:"blockWhileTunnelDown"`
	BlockedClients       []string `json:"blockedClients"`
}

// hotspotSharingEvent is the payload of HotspotSharingEvent. RestartOn names
// the connection whose profile the hotspot has to be restarted on because the
// live switch is unavailable.
type hotspotSharingEvent struct {
	Shared    string `json:"shared"`
	Blocked   bool   `json:"blocked"`
	Error     string `json:"error"`
	RestartOn string `json:"restartOn"`
}

// hotspotOS is every call the order makes on the operating system. An index
// of 0 or math.MaxUint32 names no interface.
type hotspotOS interface {
	// SharingAvailable is false when the calls that move ICS between
	// connections are missing from this Windows.
	SharingAvailable() bool
	// SharedPair fails only when ICS's pair cannot be read at all.
	SharedPair() (public, private uint32, err error)
	Share(public, private uint32) error
	Unshare(public, private uint32) error
	// TunnelIndex is the interface of the tunnel's adapter, found by its GUID.
	TunnelIndex() (uint32, bool)
	// IsPhysical says that the interface exists, is up and is not the tunnel's.
	IsPhysical(index uint32) bool
	// PhysicalIndex is the connection the PC reaches the internet through.
	PhysicalIndex() (uint32, bool)
	Forwarding(index uint32) (bool, error)
	SetForwarding(index uint32, on bool) error
	// BlockClients makes exactly these addresses unable to be forwarded.
	BlockClients(addresses []netip.Addr) error
}

type tunnelPhase int

const (
	tunnelDown tunnelPhase = iota
	tunnelConnecting
	tunnelUp
)

// tunnelPhaseOf maps an engine's lifecycle event to the tunnel's phase; ok is
// false for an event that says nothing about it.
func tunnelPhaseOf(code int32) (phase tunnelPhase, ok bool) {
	switch code {
	case EngineConnecting:
		return tunnelConnecting, true
	case EngineConnected, EngineAlreadyRunning:
		return tunnelUp, true
	case EngineError, EngineDisconnecting, EngineDisconnected:
		return tunnelDown, true
	}
	return tunnelDown, false
}

func validInterfaceIndex(index uint32) bool { return index != 0 && index != math.MaxUint32 }

// what the tunnel's state asks of ICS.
type hotspotWish int

const (
	wishHold   hotspotWish = iota // keep the pair, forward nothing
	wishTunnel                    // share the tunnel
	wishWiFi                      // share the physical connection
)

type hotspotSharing struct {
	os   hotspotOS
	emit func(payload string)
	// proxySession says that the session runs in proxy mode, which has no
	// tunnel and so is always down; nil means it never does.
	proxySession func() bool

	// workMu serialises reconciles; mu guards the state they read.
	workMu sync.Mutex
	mu     sync.Mutex

	request hotspotSharingRequest
	clients []netip.Addr
	active  bool // a request turned it on and none has turned it off since
	phase   tunnelPhase
	// shareAgain asks for a share even where ICS already points at the tunnel.
	shareAgain bool

	// worker settings, set before the first request; zero leaves reconciles
	// to the callers.
	worker bool
	every  time.Duration
	// guarded by mu
	running bool
	closed  bool
	quit    chan struct{}
	done    chan struct{}
	wake    chan struct{}

	// Owned by reconcile (workMu).
	physical       uint32
	private        uint32
	tunnelIndex    uint32 // the tunnel's interface when it was last seen
	appliedClients []netip.Addr
	clientsApplied bool
	lastEvent      string
}

// newHotspotSharing makes the order, starting from the phase the engine is
// in now.
func newHotspotSharing(os hotspotOS, emit func(string), phase tunnelPhase) *hotspotSharing {
	return &hotspotSharing{
		os:         os,
		emit:       emit,
		phase:      phase,
		shareAgain: phase == tunnelUp,
		wake:       make(chan struct{}, 1),
	}
}

// useWorker lets the order apply notify's events by itself and check a running
// hotspot every `every` (0: only on events). The worker lives while sharing is on.
func (h *hotspotSharing) useWorker(every time.Duration) {
	h.worker, h.every = true, every
}

func (h *hotspotSharing) ensureWorker() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.worker || h.running || h.closed {
		return
	}
	h.running = true
	h.quit, h.done = make(chan struct{}), make(chan struct{})
	go h.run(h.quit, h.done)
}

func (h *hotspotSharing) close() {
	h.mu.Lock()
	h.closed = true
	quit, done := h.quit, h.done
	running := h.running
	h.mu.Unlock()
	if running {
		close(quit)
		<-done
	}
}

func (h *hotspotSharing) run(quit <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	var tick <-chan time.Time
	if h.every > 0 {
		ticker := time.NewTicker(h.every)
		defer ticker.Stop()
		tick = ticker.C
	}
	for {
		select {
		case <-quit:
			return
		case <-h.wake:
		case <-tick:
		}
		h.mu.Lock()
		on := h.request.On
		if !on {
			h.running = false
		}
		h.mu.Unlock()
		if !on {
			return
		}
		h.reconcile(false)
	}
}

// set stores the whole wanted state and applies it before returning.
func (h *hotspotSharing) set(request hotspotSharingRequest) error {
	clients, err := parseBlockedClients(request.BlockedClients)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.request = request
	h.clients = clients
	if request.On {
		h.active = true
	}
	h.mu.Unlock()
	if request.On {
		h.ensureWorker()
	}
	select {
	case h.wake <- struct{}{}: // lets a worker of a request now off end
	default:
	}
	h.reconcile(true)
	return nil
}

func parseBlockedClients(raw []string) ([]netip.Addr, error) {
	if len(raw) > maxBlockedClients {
		return nil, fmt.Errorf("blockedClients: %d addresses, at most %d", len(raw), maxBlockedClients)
	}
	seen := make(map[netip.Addr]struct{}, len(raw))
	addresses := make([]netip.Addr, 0, len(raw))
	for _, text := range raw {
		address, err := netip.ParseAddr(strings.TrimSpace(text))
		if err != nil || !address.Is4() {
			return nil, fmt.Errorf("blockedClients: %q is not an IPv4 address", text)
		}
		if _, dup := seen[address]; !dup {
			seen[address] = struct{}{}
			addresses = append(addresses, address)
		}
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return addresses, nil
}

// notify tells the order about an engine lifecycle event.
func (h *hotspotSharing) notify(code int32) {
	if phase, ok := tunnelPhaseOf(code); ok {
		h.setPhase(phase)
	}
}

func (h *hotspotSharing) setPhase(phase tunnelPhase) {
	h.mu.Lock()
	if phase == tunnelUp && h.phase != tunnelUp {
		h.shareAgain = true
	}
	h.phase = phase
	on := h.request.On
	h.mu.Unlock()
	if on {
		select {
		case h.wake <- struct{}{}:
		default:
		}
	}
}

// reconcile publishes the state it ends in when it changed, or whatever it
// is when force is set: a client that just set the state wants to hear it.
func (h *hotspotSharing) reconcile(force bool) {
	h.workMu.Lock()
	defer h.workMu.Unlock()

	h.mu.Lock()
	request, clients, active, phase, again := h.request, h.clients, h.active, h.phase, h.shareAgain
	h.mu.Unlock()

	var event hotspotSharingEvent
	var problems []error
	if !request.On {
		problems = h.tearDown(active)
		event = hotspotSharingEvent{Shared: hotspotSharedNone}
	} else {
		event, problems = h.apply(request, clients, phase, again)
	}
	if len(problems) > 0 {
		event.Error = errors.Join(problems...).Error()
	}
	h.publish(event, force)
}

// tearDown ends sharing. A pair this order turned on is stopped whatever it
// points at. On a fresh core a pair is stopped only when its public side is
// the tunnel's adapter or one that is gone, what an earlier run left behind;
// a pair on a physical connection is the user's own hotspot.
func (h *hotspotSharing) tearDown(active bool) (problems []error) {
	public, private, err := h.os.SharedPair()
	if err == nil && validInterfaceIndex(private) {
		ours := active || !h.os.IsPhysical(public)
		if ours {
			if err := h.os.Unshare(public, private); err != nil {
				problems = append(problems, fmt.Errorf("stop sharing: %w", err))
			}
			// The block is lifted with the pair; the interface may be gone by now.
			_ = h.os.SetForwarding(private, true)
		}
	}
	if active {
		if err := h.os.BlockClients(nil); err != nil {
			problems = append(problems, fmt.Errorf("lift the client block: %w", err))
		}
	}
	h.appliedClients, h.clientsApplied = nil, false
	h.physical, h.private, h.tunnelIndex = 0, 0, 0
	h.mu.Lock()
	h.active = false
	h.shareAgain = false
	h.mu.Unlock()
	return problems
}

// wishFor says what the tunnel's state asks of ICS: the effective phase, since
// the engine's events and the adapter must agree for the tunnel to count as up
// and as down.
func (h *hotspotSharing) wishFor(request hotspotSharingRequest, phase tunnelPhase, tunnelPresent bool) hotspotWish {
	proxy := h.proxySession != nil && h.proxySession()
	switch {
	case phase == tunnelConnecting && !proxy:
		return wishHold
	case phase == tunnelUp && !proxy:
		if tunnelPresent {
			return wishTunnel
		}
		return wishHold
	case tunnelPresent:
		// The engine says it is down and its adapter has not gone yet.
		return wishHold
	case request.BlockWhileTunnelDown:
		return wishHold
	}
	return wishWiFi
}

func (h *hotspotSharing) apply(request hotspotSharingRequest, clients []netip.Addr, phase tunnelPhase, again bool) (event hotspotSharingEvent, problems []error) {
	if !h.clientsApplied || !slices.Equal(h.appliedClients, clients) {
		if err := h.os.BlockClients(clients); err != nil {
			problems = append(problems, fmt.Errorf("block clients: %w", err))
		} else {
			h.appliedClients, h.clientsApplied = slices.Clone(clients), true
		}
	}

	public, private, err := h.os.SharedPair()
	if err != nil {
		problems = append(problems, fmt.Errorf("read the shared connection: %w", err))
		public, private = math.MaxUint32, h.private
	}
	if validInterfaceIndex(private) {
		h.private = private
	} else if err == nil {
		return hotspotSharingEvent{Shared: hotspotSharedNone}, problems
	}

	tunnel, tunnelPresent := h.os.TunnelIndex()
	if tunnelPresent {
		h.tunnelIndex = tunnel
	}
	if validInterfaceIndex(public) && (!tunnelPresent || public != tunnel) && h.os.IsPhysical(public) {
		h.physical = public
	}

	wish := h.wishFor(request, phase, tunnelPresent)
	var want uint32
	kind := ""
	switch wish {
	case wishTunnel:
		want, kind = tunnel, hotspotSharedTunnel
	case wishWiFi:
		kind = hotspotSharedWiFi
		want = h.physicalConnection()
		if !validInterfaceIndex(want) {
			problems = append(problems, errors.New("no connection to share"))
		}
	}

	if validInterfaceIndex(want) && (public != want || (wish == wishTunnel && again && h.os.SharingAvailable())) {
		if shareErr := h.share(public, want, private); shareErr != nil {
			problems = append(problems, fmt.Errorf("share the %s connection: %w", kind, shareErr))
			if !h.os.SharingAvailable() || validInterfaceIndex(private) {
				event.RestartOn = kind
			}
		} else {
			h.mu.Lock()
			h.shareAgain = false
			h.mu.Unlock()
		}
	}

	now, nowPrivate, nowErr := h.os.SharedPair()
	if nowErr == nil && validInterfaceIndex(nowPrivate) {
		private = nowPrivate
		h.private = nowPrivate
	}
	forwardingOn := validInterfaceIndex(want) && nowErr == nil && now == want
	if validInterfaceIndex(private) {
		if err := h.settleForwarding(private, forwardingOn); err != nil {
			problems = append(problems, err)
		} else {
			event.Blocked = !forwardingOn
		}
	}

	event.Shared = hotspotSharedNone
	if nowErr == nil && validInterfaceIndex(now) {
		event.Shared = hotspotSharedWiFi
		if now == h.tunnelIndex {
			event.Shared = hotspotSharedTunnel
		}
	}
	return event, problems
}

// physicalConnection is the connection to share while the tunnel is down. An
// index of an adapter that is gone is never it.
func (h *hotspotSharing) physicalConnection() uint32 {
	if validInterfaceIndex(h.physical) && h.os.IsPhysical(h.physical) {
		return h.physical
	}
	if index, ok := h.os.PhysicalIndex(); ok {
		h.physical = index
		return index
	}
	h.physical = 0
	return 0
}

// share moves ICS to public: by a start alone, and, when ICS refuses that with
// a pair standing, by stopping the pair first. It does not need a private side
// to report that the live switch is missing.
func (h *hotspotSharing) share(current, public, private uint32) error {
	if !h.os.SharingAvailable() {
		return errors.New("the live switch is unavailable on this Windows")
	}
	if !validInterfaceIndex(private) {
		return errors.New("no hotspot interface")
	}
	err := h.os.Share(public, private)
	if err != nil && validInterfaceIndex(current) {
		if stopErr := h.os.Unshare(current, private); stopErr == nil {
			err = h.os.Share(public, private)
		}
	}
	return err
}

// settleForwarding makes forwarding on the hotspot's interface what it should
// be. A forwarding state that cannot be read is set anyway.
func (h *hotspotSharing) settleForwarding(private uint32, on bool) error {
	current, readErr := h.os.Forwarding(private)
	if readErr == nil && current == on {
		return nil
	}
	if err := h.os.SetForwarding(private, on); err != nil {
		return fmt.Errorf("set forwarding: %w", err)
	}
	return nil
}

func (h *hotspotSharing) publish(event hotspotSharingEvent, force bool) {
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}
	text := string(payload)
	if text == h.lastEvent && !force {
		return
	}
	h.lastEvent = text
	h.emit(text)
}

// lastPublished is the event to replay to a client that attaches later.
func (h *hotspotSharing) lastPublished() string {
	h.workMu.Lock()
	defer h.workMu.Unlock()
	return h.lastEvent
}
