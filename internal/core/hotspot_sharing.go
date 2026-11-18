package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
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
//
// What the order knows about the pair is what it did itself, a successful
// share of a public side with the hotspot's adapter. What ICS reports can only
// take that knowledge away.

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

// hotspotAdapterGrace is how long a hotspot that should run may have no adapter
// up before the event says so: the plugin starts it after it asks for sharing,
// and an adapter that goes away comes back with a restart.
const hotspotAdapterGrace = 10 * time.Second

// maxBlockedClients bounds the per-device filters one hotspot holds.
const maxBlockedClients = 8

type hotspotSharingRequest struct {
	On                   bool     `json:"on"`
	BlockWhileTunnelDown bool     `json:"blockWhileTunnelDown"`
	BlockedClients       []string `json:"blockedClients"`
}

// hotspotSharingEvent is the payload of HotspotSharingEvent. A share ICS refused
// is Shared "none" with an Error.
type hotspotSharingEvent struct {
	Shared  string `json:"shared"`
	Blocked bool   `json:"blocked"`
	Error   string `json:"error"`
}

// hotspotOS is every call the order makes on the operating system. An index
// of 0 or math.MaxUint32 names no interface.
type hotspotOS interface {
	// SharingAvailable is false when the calls that move ICS between
	// connections are missing from this Windows.
	SharingAvailable() bool
	// SharedPair is what ICS reports, read from a record any local user can
	// write: it can take a share the order made away, and names the public
	// side of a pair being stopped. It fails when the pair cannot be read.
	SharedPair() (public, private uint32, err error)
	Share(public, private uint32) error
	Unshare(public, private uint32) error
	// TunnelIndex is the interface of the tunnel's adapter, found by its GUID.
	TunnelIndex() (uint32, bool)
	// HotspotAdapters are the interfaces of the Wi-Fi Direct virtual adapters
	// that are up, found by the driver's identity; the Mobile hotspot runs on
	// one of them. It fails when they cannot be listed.
	HotspotAdapters() ([]uint32, error)
	// IsPhysical says that the interface exists and is neither the tunnel's
	// nor a loopback; whether it is up is not its question.
	IsPhysical(index uint32) bool
	IsUp(index uint32) bool
	// PhysicalIndex is the connection the PC reaches the internet through.
	PhysicalIndex() (uint32, bool)
	Forwarding(index uint32) (bool, error)
	SetForwarding(index uint32, on bool) error
	// BlockClients drops every frame the devices with exactly these MAC
	// addresses send in on the hotspot's interface; none, or no interface (0),
	// lifts the block.
	BlockClients(hotspot uint32, macs []net.HardwareAddr) error
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

// sharedRecord is what the order itself shared and has not had reason to
// doubt since: the public side of its last successful share, and the hotspot
// adapter it was shared with.
type sharedRecord struct {
	ok      bool
	public  uint32
	hotspot uint32
}

func (r sharedRecord) holds(public, hotspot uint32) bool {
	return r.ok && r.public == public && r.hotspot == hotspot
}

type hotspotSharing struct {
	os   hotspotOS
	emit func(payload string)
	// proxySession says that the session runs in proxy mode, which has no
	// tunnel and so is always down; nil means it never does.
	proxySession func() bool
	// now is the clock the grace period reads.
	now func() time.Time

	// workMu serialises reconciles; mu guards the state they read.
	workMu sync.Mutex
	mu     sync.Mutex

	request hotspotSharingRequest
	clients []net.HardwareAddr
	active  bool // a request turned it on and none has turned it off since
	phase   tunnelPhase
	// shareAgain asks for a share even where the record already holds it:
	// after every request and every tunnel-up.
	shareAgain bool
	// publishNext makes the next reconcile publish its state even if it did not
	// change: a client that just set the state wants to hear it.
	publishNext bool
	lastEvent   string
	// requested counts the requests, so a worker that applied an off knows
	// whether another arrived while it did.
	requested uint64

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
	shared sharedRecord
	// lastShared is the pair this order last shared, kept until an off has
	// stopped it, whether or not the adapter is still there.
	lastShared     sharedRecord
	noAdapterSince time.Time // since when sharing is on and no adapter is up; zero when one is
	hotspot        uint32    // the hotspot's adapter at the last reconcile; 0 when none was up
	forwardingOff  uint32    // the adapter this order turned forwarding off on; 0 when none
	physical       uint32    // the connection this order last shared as the physical one
	tunnelIndex    uint32    // the tunnel's interface when it was last seen
	appliedClients []net.HardwareAddr
	appliedOn      uint32 // the interface the block was applied on; 0 for none
	clientsApplied bool
}

// newHotspotSharing makes the order, starting from the phase the engine is
// in now.
func newHotspotSharing(os hotspotOS, emit func(string), phase tunnelPhase) *hotspotSharing {
	return &hotspotSharing{
		os:    os,
		emit:  emit,
		phase: phase,
		now:   time.Now,
		wake:  make(chan struct{}, 1),
	}
}

// adoptPhase takes the engine's phase as read inside the order's own lock, so
// an event delivered through setPhase meanwhile is never overwritten by an
// older reading.
func (h *hotspotSharing) adoptPhase(current func() tunnelPhase) {
	h.mu.Lock()
	h.phase = current()
	h.mu.Unlock()
}

// useWorker lets the order apply requests and notify's events by itself, off
// the caller, and check a running hotspot every `every` (0: only on events).
// The worker lives while sharing is on and ends once it has applied an off.
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
	h.quit, h.done = nil, nil
	h.mu.Unlock()
	if quit != nil {
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
		appliedOn, generation := h.reconcile()
		if appliedOn {
			continue
		}
		// An off was applied. A request that arrived while it was has sent its
		// own wake, which this worker is then still here to take.
		h.mu.Lock()
		if !h.request.On && h.requested == generation {
			h.running = false
			h.mu.Unlock()
			return
		}
		h.mu.Unlock()
	}
}

// set stores the whole wanted state. With a worker it hands the state over and
// returns, so a caller holding a lock of its own never waits behind a
// reconcile; without one it applies the state before returning.
func (h *hotspotSharing) set(request hotspotSharingRequest) error {
	clients, err := parseBlockedClients(request.BlockedClients)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.request = request
	h.clients = clients
	h.publishNext = true
	h.requested++
	if request.On {
		h.active = true
		h.shareAgain = true
	}
	h.mu.Unlock()
	if !h.worker {
		h.reconcile()
		return nil
	}
	h.ensureWorker()
	select {
	case h.wake <- struct{}{}:
	default:
	}
	return nil
}

// parseBlockedClients reads the MAC addresses of the blocked devices, sorted
// and without duplicates.
func parseBlockedClients(raw []string) ([]net.HardwareAddr, error) {
	if len(raw) > maxBlockedClients {
		return nil, fmt.Errorf("blockedClients: %d addresses, at most %d", len(raw), maxBlockedClients)
	}
	seen := make(map[string]struct{}, len(raw))
	macs := make([]net.HardwareAddr, 0, len(raw))
	for _, text := range raw {
		mac, err := net.ParseMAC(strings.TrimSpace(text))
		if err != nil || len(mac) != 6 {
			return nil, fmt.Errorf("blockedClients: %q is not a MAC address", text)
		}
		if _, dup := seen[mac.String()]; !dup {
			seen[mac.String()] = struct{}{}
			macs = append(macs, mac)
		}
	}
	slices.SortFunc(macs, func(a, b net.HardwareAddr) int { return bytes.Compare(a, b) })
	return macs, nil
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

// reconcile applies the stored state and publishes the state it ends in when
// it changed, or whatever it is after a set. It returns whether the state it
// applied was on, and which request that was.
func (h *hotspotSharing) reconcile() (appliedOn bool, generation uint64) {
	h.workMu.Lock()
	defer h.workMu.Unlock()

	h.mu.Lock()
	request, clients, active, phase, again := h.request, h.clients, h.active, h.phase, h.shareAgain
	generation = h.requested
	publishNext := h.publishNext
	h.publishNext, h.shareAgain = false, false
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
	h.publish(event, publishNext)
	return request.On, generation
}

// tearDown ends sharing. The pair this order last shared is stopped by the
// indices it shared, whatever it points at and even when the hotspot's adapter
// has gone, since an off usually arrives after the hotspot is down. A pair it
// did not share, one that ICS reports for the hotspot's adapter, is stopped only
// when its public side is the tunnel's adapter or one that is gone, what an
// earlier run left behind; a pair on a physical connection is the user's own
// hotspot. Forwarding is given back only on the hotspot's adapter that is there.
func (h *hotspotSharing) tearDown(active bool) (problems []error) {
	hotspot, found, problem := h.findHotspot(false)
	if problem != nil {
		problems = append(problems, problem)
	}
	stoppedOn := uint32(0)
	if h.lastShared.ok {
		err := h.os.Unshare(h.lastShared.public, h.lastShared.hotspot)
		if err != nil && found {
			problems = append(problems, fmt.Errorf("stop sharing: %w", err))
		}
		stoppedOn = h.lastShared.hotspot
	} else if found {
		reported, private, pairErr := h.os.SharedPair()
		if pairErr == nil && private == hotspot && !h.os.IsPhysical(reported) {
			if err := h.os.Unshare(reported, hotspot); err != nil {
				problems = append(problems, fmt.Errorf("stop sharing: %w", err))
			}
			stoppedOn = hotspot
		}
	}
	// What this order turned off, or ended the pair of, is given back; the
	// interface may be gone by now.
	if found && ((stoppedOn != 0 && stoppedOn == hotspot) || h.forwardingOff == hotspot) {
		_ = h.os.SetForwarding(hotspot, true)
	}
	if active {
		if err := h.os.BlockClients(0, nil); err != nil {
			problems = append(problems, fmt.Errorf("lift the client block: %w", err))
		}
	}
	h.appliedClients, h.appliedOn, h.clientsApplied = nil, 0, false
	h.shared, h.lastShared, h.hotspot, h.forwardingOff = sharedRecord{}, sharedRecord{}, 0, 0
	h.noAdapterSince = time.Time{}
	h.physical, h.tunnelIndex = 0, 0
	h.mu.Lock()
	// A request that turned sharing on since this one was read keeps its flags.
	if !h.request.On {
		h.active = false
		h.shareAgain = false
	}
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

func (h *hotspotSharing) apply(request hotspotSharingRequest, clients []net.HardwareAddr, phase tunnelPhase, again bool) (event hotspotSharingEvent, problems []error) {
	hotspot, found, problem := h.findHotspot(true)
	if problem != nil {
		problems = append(problems, problem)
	} else {
		// Where the hotspot's adapter is unknown, the block stays as it was;
		// where none is up there are no clients to block.
		problems = append(problems, h.settleBlock(hotspot, clients)...)
	}
	if !found {
		// A share of an adapter that is gone is not trusted when one comes back.
		h.shared = sharedRecord{}
		h.shareAgainLater(again)
		// Nothing is forwarded on an adapter that is not there, and one that
		// could not be told is turned off where it was known: blocked says so
		// only where the core did that.
		event = hotspotSharingEvent{Shared: hotspotSharedNone, Blocked: problem == nil || h.forwardingOff != 0}
		if problem == nil {
			// The list was read and none is up; what was known of an adapter is over.
			h.hotspot, h.forwardingOff = 0, 0
			problems = append(problems, h.waitForAdapter()...)
		}
		return event, problems
	}
	h.noAdapterSince = time.Time{}
	if hotspot != h.hotspot {
		h.shared, h.forwardingOff = sharedRecord{}, 0
		h.hotspot = hotspot
	}
	if h.shared.ok {
		// ICS says it is not where this order left it: something else moved it.
		// The report is believed only that way.
		if public, private, err := h.os.SharedPair(); err == nil && (public != h.shared.public || private != h.shared.hotspot) {
			h.shared = sharedRecord{}
		}
	}

	tunnel, tunnelPresent := h.os.TunnelIndex()
	if tunnelPresent {
		h.tunnelIndex = tunnel
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

	// ICS may stand on the physical connection: nothing is forwarded while it
	// moves to the tunnel.
	if wish == wishTunnel && !h.shared.holds(want, hotspot) {
		if err := h.settleForwarding(hotspot, false); err != nil {
			problems = append(problems, err)
		}
	}

	if validInterfaceIndex(want) && (again || !h.shared.holds(want, hotspot)) {
		if shareErr := h.share(want, hotspot); shareErr != nil {
			h.shared = sharedRecord{}
			problems = append(problems, fmt.Errorf("share the %s connection: %w", kind, shareErr))
		} else {
			h.shared = sharedRecord{ok: true, public: want, hotspot: hotspot}
			h.lastShared = h.shared
			if wish == wishWiFi {
				h.physical = want
			}
		}
	} else {
		h.shareAgainLater(again)
	}

	forwardingOn := validInterfaceIndex(want) && h.shared.holds(want, hotspot)
	if err := h.settleForwarding(hotspot, forwardingOn); err != nil {
		problems = append(problems, err)
	} else {
		event.Blocked = !forwardingOn
	}

	event.Shared = hotspotSharedNone
	if h.shared.ok && h.shared.hotspot == hotspot {
		event.Shared = hotspotSharedWiFi
		if h.shared.public == h.tunnelIndex {
			event.Shared = hotspotSharedTunnel
		}
	}
	return event, problems
}

// findHotspot is the hotspot's interface: the one Wi-Fi Direct adapter that is
// up. With several up (a hotspot beside a wireless display) which is the
// hotspot's cannot be told, and with the adapters unlisted nothing is known:
// nothing is shared or stopped on a guess, and with block set forwarding is
// turned off on every adapter that might be it.
func (h *hotspotSharing) findHotspot(block bool) (index uint32, found bool, problem error) {
	up, err := h.os.HotspotAdapters()
	switch {
	case err != nil:
		problem = fmt.Errorf("find the hotspot's interface: %w", err)
		if block && validInterfaceIndex(h.hotspot) {
			up = []uint32{h.hotspot}
		} else {
			up = nil
		}
	case len(up) == 1:
		return up[0], true, nil
	case len(up) > 1:
		problem = fmt.Errorf("find the hotspot's interface: %d Wi-Fi Direct adapters are up", len(up))
	}
	if block {
		for _, candidate := range up {
			if err := h.settleForwarding(candidate, false); err != nil {
				problem = errors.Join(problem, err)
				h.forwardingOff = 0
			}
		}
	}
	return 0, false, problem
}

// settleBlock holds the block on the hotspot's interface, or lifts it where
// there is none (0).
func (h *hotspotSharing) settleBlock(hotspot uint32, clients []net.HardwareAddr) []error {
	if hotspot == 0 {
		clients = nil
	}
	same := slices.EqualFunc(h.appliedClients, clients, func(a, b net.HardwareAddr) bool { return bytes.Equal(a, b) })
	if h.clientsApplied && h.appliedOn == hotspot && same {
		return nil
	}
	if err := h.os.BlockClients(hotspot, clients); err != nil {
		return []error{fmt.Errorf("block clients: %w", err)}
	}
	h.appliedClients, h.appliedOn, h.clientsApplied = slices.Clone(clients), hotspot, true
	return nil
}

// waitForAdapter is quiet while a hotspot that should run has no adapter up for
// a grace period, and an error after it.
func (h *hotspotSharing) waitForAdapter() []error {
	now := h.now()
	if h.noAdapterSince.IsZero() {
		h.noAdapterSince = now
		return nil
	}
	if now.Sub(h.noAdapterSince) >= hotspotAdapterGrace {
		return []error{errors.New("no hotspot adapter is up")}
	}
	return nil
}

// shareAgainLater keeps a request for a share that had nothing to share yet.
func (h *hotspotSharing) shareAgainLater(again bool) {
	if !again {
		return
	}
	h.mu.Lock()
	h.shareAgain = true
	h.mu.Unlock()
}

// physicalConnection is the connection to share while the tunnel is down: the
// one this order shared last, while it exists and is up, else the PC's own. An
// index of an adapter that is gone is never it.
func (h *hotspotSharing) physicalConnection() uint32 {
	if validInterfaceIndex(h.physical) && h.os.IsPhysical(h.physical) && h.os.IsUp(h.physical) {
		return h.physical
	}
	h.physical = 0
	if index, ok := h.os.PhysicalIndex(); ok {
		return index
	}
	return 0
}

// share moves ICS to public, with the hotspot's adapter as the private side: by
// a start alone, and, when ICS refuses that with a pair standing, by stopping
// the pair first.
func (h *hotspotSharing) share(public, hotspot uint32) error {
	if !h.os.SharingAvailable() {
		return errors.New("the live switch is unavailable on this Windows")
	}
	err := h.os.Share(public, hotspot)
	if err == nil {
		return nil
	}
	if current, ok := h.standingPublic(hotspot); ok {
		if stopErr := h.os.Unshare(current, hotspot); stopErr == nil {
			err = h.os.Share(public, hotspot)
		}
	}
	return err
}

// standingPublic is the public side of the pair that stands with the hotspot's
// adapter: the one this order shared, else the one ICS reports.
func (h *hotspotSharing) standingPublic(hotspot uint32) (uint32, bool) {
	if h.shared.ok && h.shared.hotspot == hotspot {
		return h.shared.public, true
	}
	public, private, err := h.os.SharedPair()
	return public, err == nil && private == hotspot && validInterfaceIndex(public)
}

// settleForwarding makes forwarding on the hotspot's interface what it should
// be. A forwarding state that cannot be read is set anyway.
func (h *hotspotSharing) settleForwarding(hotspot uint32, on bool) error {
	current, readErr := h.os.Forwarding(hotspot)
	if readErr != nil || current != on {
		if err := h.os.SetForwarding(hotspot, on); err != nil {
			return fmt.Errorf("set forwarding: %w", err)
		}
	}
	if on {
		h.forwardingOff = 0
	} else {
		h.forwardingOff = hotspot
	}
	return nil
}

func (h *hotspotSharing) publish(event hotspotSharingEvent, force bool) {
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}
	text := string(payload)
	h.mu.Lock()
	unchanged := text == h.lastEvent
	h.lastEvent = text
	h.mu.Unlock()
	if unchanged && !force {
		return
	}
	h.emit(text)
}

// lastPublished is the event to replay to a client that attaches later.
func (h *hotspotSharing) lastPublished() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastEvent
}
