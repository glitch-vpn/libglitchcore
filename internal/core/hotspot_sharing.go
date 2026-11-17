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
	SharedPair() (public, private uint32, err error)
	Share(public, private uint32) error
	Unshare(public, private uint32) error
	TunnelIndex() (uint32, bool)
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

type hotspotSharing struct {
	os   hotspotOS
	emit func(payload string)

	// workMu serialises reconciles; mu guards the state they read.
	workMu sync.Mutex
	mu     sync.Mutex

	request hotspotSharingRequest
	clients []netip.Addr
	active  bool // a request turned it on and none has turned it off since
	phase   tunnelPhase
	// shareAgain asks for a share even where ICS already points at the tunnel.
	shareAgain bool

	// Owned by reconcile (workMu).
	physical       uint32
	tunnelIndex    uint32
	appliedClients []netip.Addr
	clientsApplied bool
	lastEvent      string

	started bool
	wake    chan struct{}
	quit    chan struct{}
	done    chan struct{}
}

func newHotspotSharing(os hotspotOS, emit func(string)) *hotspotSharing {
	return &hotspotSharing{
		os:   os,
		emit: emit,
		wake: make(chan struct{}, 1),
		quit: make(chan struct{}),
		done: make(chan struct{}),
	}
}

// start runs the worker that applies what notify wakes it for, and checks a
// running hotspot every `every` (0 leaves the periodic check off).
func (h *hotspotSharing) start(every time.Duration) {
	h.started = true
	go h.run(every)
}

func (h *hotspotSharing) close() {
	if !h.started {
		return
	}
	close(h.quit)
	<-h.done
}

func (h *hotspotSharing) run(every time.Duration) {
	defer close(h.done)
	var tick <-chan time.Time
	if every > 0 {
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		tick = ticker.C
	}
	for {
		select {
		case <-h.quit:
			return
		case <-h.wake:
		case <-tick:
		}
		h.mu.Lock()
		on := h.request.On
		h.mu.Unlock()
		if on {
			h.reconcile(false)
		}
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
	h.reconcile(true)
	return nil
}

func parseBlockedClients(raw []string) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0, len(raw))
	for _, text := range raw {
		address, err := netip.ParseAddr(strings.TrimSpace(text))
		if err != nil || !address.Is4() {
			return nil, fmt.Errorf("blockedClients: %q is not an IPv4 address", text)
		}
		if !slices.Contains(addresses, address) {
			addresses = append(addresses, address)
		}
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return addresses, nil
}

// notify tells the order about an engine lifecycle event.
func (h *hotspotSharing) notify(code int32) {
	phase, ok := tunnelPhaseOf(code)
	if !ok {
		return
	}
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
		if active {
			problems = h.tearDown()
		}
		event = hotspotSharingEvent{Shared: hotspotSharedNone}
	} else {
		event, problems = h.apply(request, clients, phase, again)
	}
	if len(problems) > 0 {
		event.Error = errors.Join(problems...).Error()
	}
	h.publish(event, force)
}

func (h *hotspotSharing) tearDown() (problems []error) {
	public, private, err := h.os.SharedPair()
	if err == nil && (validInterfaceIndex(public) || validInterfaceIndex(private)) {
		if err := h.os.Unshare(public, private); err != nil {
			problems = append(problems, fmt.Errorf("stop sharing: %w", err))
		}
	}
	if err := h.os.BlockClients(nil); err != nil {
		problems = append(problems, fmt.Errorf("lift the client block: %w", err))
	}
	h.appliedClients, h.clientsApplied = nil, false
	h.physical, h.tunnelIndex = 0, 0
	h.mu.Lock()
	h.active = false
	h.shareAgain = false
	h.mu.Unlock()
	return problems
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
		return hotspotSharingEvent{Shared: hotspotSharedNone}, problems
	}
	if !validInterfaceIndex(private) {
		return hotspotSharingEvent{Shared: hotspotSharedNone}, problems
	}

	// A tunnel that is up with no adapter is proxy mode: nothing to share.
	tunnel, haveTunnel := h.os.TunnelIndex()
	if haveTunnel {
		h.tunnelIndex = tunnel
	}
	if phase == tunnelUp && !haveTunnel {
		phase = tunnelDown
	}
	if validInterfaceIndex(public) && public != h.tunnelIndex {
		h.physical = public
	}

	// Where ICS already points is all that a stopped live switch can ask for.
	if again && !h.os.SharingAvailable() {
		again = false
		h.mu.Lock()
		h.shareAgain = false
		h.mu.Unlock()
	}

	var wantPublic uint32
	forwardingOff := false
	switch {
	case phase == tunnelUp:
		wantPublic = tunnel
	case phase == tunnelConnecting:
		// No window in which clients leave around a tunnel that is coming up.
		forwardingOff = true
	case request.BlockWhileTunnelDown:
		forwardingOff = true
	default:
		wantPublic = h.physical
		if !validInterfaceIndex(wantPublic) {
			if index, ok := h.os.PhysicalIndex(); ok {
				wantPublic, h.physical = index, index
			} else {
				problems = append(problems, errors.New("no connection to share"))
			}
		}
	}

	if validInterfaceIndex(wantPublic) && (public != wantPublic || (phase == tunnelUp && again)) {
		kind := hotspotSharedWiFi
		if phase == tunnelUp {
			kind = hotspotSharedTunnel
		}
		if err := h.share(public, wantPublic, private); err != nil {
			problems = append(problems, fmt.Errorf("share the %s connection: %w", kind, err))
			event.RestartOn = kind
		} else {
			h.mu.Lock()
			h.shareAgain = false
			h.mu.Unlock()
			// Every start turns forwarding on again.
			if forwardingOff {
				if err := h.os.SetForwarding(private, false); err != nil {
					problems = append(problems, fmt.Errorf("turn forwarding off: %w", err))
				}
			}
		}
	}

	blocked, err := h.settleForwarding(private, forwardingOff)
	if err != nil {
		problems = append(problems, err)
	}
	event.Blocked = blocked

	event.Shared = hotspotSharedNone
	if now, _, err := h.os.SharedPair(); err == nil && validInterfaceIndex(now) {
		event.Shared = hotspotSharedWiFi
		if now == h.tunnelIndex {
			event.Shared = hotspotSharedTunnel
		}
	}
	return event, problems
}

// share moves ICS to public: by a start alone, and, when ICS refuses that with
// a pair standing, by stopping the pair first.
func (h *hotspotSharing) share(current, public, private uint32) error {
	if !h.os.SharingAvailable() {
		return errors.New("the live switch is unavailable on this Windows")
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
// be, and reports whether the block is in place.
func (h *hotspotSharing) settleForwarding(private uint32, off bool) (blocked bool, err error) {
	on, err := h.os.Forwarding(private)
	if err != nil {
		return false, fmt.Errorf("read forwarding: %w", err)
	}
	if on == !off {
		return off, nil
	}
	if err := h.os.SetForwarding(private, !off); err != nil {
		return false, fmt.Errorf("set forwarding: %w", err)
	}
	return off, nil
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
