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
	"testing"
	"time"
)

const (
	testWiFi      = 4
	testTunnel    = 7
	testHotspot   = 9
	testLAN       = 12 // another connection of the PC, with no part in the hotspot
	testGoneIndex = 30
)

// fakeHotspotOS behaves as ICS does: a share sets the pair and turns
// forwarding on for the private side. public and private are the pair ICS
// really holds; what SharedPair reports is that, unless forged is set, as a
// local user can make it. It records every state in which forwarding was on
// while the real pair pointed somewhere the step does not allow.
type fakeHotspotOS struct {
	mu sync.Mutex

	available  bool
	public     uint32
	private    uint32
	forged     *[2]uint32 // what SharedPair reports instead of the real pair
	tunnel     uint32     // 0: no adapter
	present    map[uint32]bool
	physical   uint32
	pairErr    error
	hotspot    uint32 // the hotspot's adapter
	hotspotUp  bool
	otherWFD   []uint32 // other Wi-Fi Direct adapters that are up
	hotspotErr error
	forwarding map[uint32]bool
	clients    []netip.Addr

	shareErr   error
	shareFails int // how many Share calls still fail
	calls      []string

	allowed map[uint32]bool // nil: not checked
	leaks   []string
}

func newFakeHotspotOS() *fakeHotspotOS {
	return &fakeHotspotOS{
		available:  true,
		public:     testWiFi,
		private:    testHotspot,
		physical:   testWiFi,
		present:    map[uint32]bool{testWiFi: true, testLAN: true, testHotspot: true},
		hotspot:    testHotspot,
		hotspotUp:  true,
		forwarding: map[uint32]bool{testHotspot: true},
	}
}

func (f *fakeHotspotOS) record(format string, args ...any) {
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
}

// checkLeak runs after a call that changes the pair or forwarding.
func (f *fakeHotspotOS) checkLeak(call string) {
	if f.allowed != nil && f.forwarding[f.private] && validInterfaceIndex(f.private) && !f.allowed[f.public] {
		f.leaks = append(f.leaks, fmt.Sprintf("after %s: forwarding on with ICS public %d", call, f.public))
	}
}

func (f *fakeHotspotOS) callsMatching(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, call := range f.calls {
		if strings.HasPrefix(call, prefix) {
			count++
		}
	}
	return count
}

func (f *fakeHotspotOS) SharingAvailable() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.available
}

func (f *fakeHotspotOS) SharedPair() (uint32, uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pairErr != nil {
		return math.MaxUint32, math.MaxUint32, f.pairErr
	}
	if f.forged != nil {
		return f.forged[0], f.forged[1], nil
	}
	return f.public, f.private, nil
}

func (f *fakeHotspotOS) Share(public, private uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("share %d %d", public, private)
	if f.shareFails > 0 {
		f.shareFails--
		return errors.New("refused")
	}
	if f.shareErr != nil {
		return f.shareErr
	}
	f.public, f.private = public, private
	f.forwarding[private] = true
	f.checkLeak("share")
	return nil
}

func (f *fakeHotspotOS) Unshare(public, private uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("unshare %d %d", public, private)
	if public != f.public || private != f.private {
		return errors.New("no such pair")
	}
	f.public, f.private = math.MaxUint32, math.MaxUint32
	return nil
}

func (f *fakeHotspotOS) TunnelIndex() (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tunnel, f.tunnel != 0
}

func (f *fakeHotspotOS) HotspotAdapters() ([]uint32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hotspotErr != nil {
		return nil, f.hotspotErr
	}
	var up []uint32
	if f.hotspotUp {
		up = append(up, f.hotspot)
	}
	return append(up, f.otherWFD...), nil
}

func (f *fakeHotspotOS) IsPhysical(index uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.present[index] && index != f.tunnel
}

func (f *fakeHotspotOS) PhysicalIndex() (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.physical, f.physical != 0
}

func (f *fakeHotspotOS) Forwarding(index uint32) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.forwarding[index], nil
}

func (f *fakeHotspotOS) SetForwarding(index uint32, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("forwarding %d %t", index, on)
	f.forwarding[index] = on
	f.checkLeak("forwarding")
	return nil
}

func (f *fakeHotspotOS) BlockClients(addresses []netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("clients %v", addresses)
	f.clients = slices.Clone(addresses)
	return nil
}

type hotspotFixture struct {
	t       *testing.T
	os      *fakeHotspotOS
	sharing *hotspotSharing
	events  []hotspotSharingEvent
}

func newHotspotFixture(t *testing.T) *hotspotFixture {
	t.Helper()
	return newHotspotFixtureAt(t, tunnelDown)
}

func newHotspotFixtureAt(t *testing.T, phase tunnelPhase) *hotspotFixture {
	t.Helper()
	fixture := &hotspotFixture{t: t, os: newFakeHotspotOS()}
	fixture.sharing = newHotspotSharing(fixture.os, func(payload string) {
		var event hotspotSharingEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			t.Errorf("event %q is not JSON: %v", payload, err)
		}
		fixture.events = append(fixture.events, event)
	}, phase)
	t.Cleanup(func() {
		if len(fixture.os.leaks) > 0 {
			t.Errorf("forwarding leaked: %v", fixture.os.leaks)
		}
	})
	return fixture
}

// allow names the ICS public sides on which forwarding may be on from the
// next step on; with none, every state with forwarding on is a leak.
func (f *hotspotFixture) allow(indexes ...uint32) {
	f.os.mu.Lock()
	defer f.os.mu.Unlock()
	f.os.allowed = map[uint32]bool{}
	for _, index := range indexes {
		f.os.allowed[index] = true
	}
}

func (f *hotspotFixture) set(on, block bool, clients ...string) {
	f.t.Helper()
	if err := f.sharing.set(hotspotSharingRequest{On: on, BlockWhileTunnelDown: block, BlockedClients: clients}); err != nil {
		f.t.Fatalf("set: %v", err)
	}
}

// engineEvent sends a lifecycle event as the engine does, with the adapter
// where it is then: there from Connected until Disconnected has been said.
func (f *hotspotFixture) engineEvent(code int32) {
	f.t.Helper()
	f.os.mu.Lock()
	switch code {
	case EngineConnected:
		f.os.tunnel = testTunnel
		f.os.present[testTunnel] = true
	case EngineDisconnected:
		f.os.tunnel = 0
		delete(f.os.present, testTunnel)
	}
	f.os.mu.Unlock()
	f.sharing.notify(code)
	f.sharing.reconcile()
}

func (f *hotspotFixture) last() hotspotSharingEvent {
	f.t.Helper()
	if len(f.events) == 0 {
		f.t.Fatal("no event was emitted")
	}
	return f.events[len(f.events)-1]
}

func (f *hotspotFixture) wantState(shared string, blocked bool, public uint32, forwarding bool) {
	f.t.Helper()
	event := f.last()
	if event.Shared != shared || event.Blocked != blocked {
		f.t.Errorf("event = %+v, want shared %q blocked %t", event, shared, blocked)
	}
	if event.Error != "" || event.RestartOn != "" {
		f.t.Errorf("event = %+v, want no error and no restart", event)
	}
	f.wantPair(public, forwarding)
}

func (f *hotspotFixture) wantPair(public uint32, forwarding bool) {
	f.t.Helper()
	if f.os.public != public {
		f.t.Errorf("ICS public = %d, want %d", f.os.public, public)
	}
	if f.os.forwarding[testHotspot] != forwarding {
		f.t.Errorf("forwarding on the hotspot = %t, want %t", f.os.forwarding[testHotspot], forwarding)
	}
}

func TestHotspotSharingStartedWithTunnelDown(t *testing.T) {
	t.Run("block=true", func(t *testing.T) {
		f := newHotspotFixture(t)
		f.allow()
		f.set(true, true)
		// Windows started the hotspot on the Wi-Fi with forwarding on; the block
		// goes on at once and nothing is shared.
		f.wantState(hotspotSharedNone, true, testWiFi, false)
		if f.os.callsMatching("share") != 0 {
			t.Errorf("shared with the tunnel down and the block on: %v", f.os.calls)
		}
	})
	t.Run("block=false", func(t *testing.T) {
		f := newHotspotFixture(t)
		f.allow(testWiFi)
		f.set(true, false)
		f.wantState(hotspotSharedWiFi, false, testWiFi, true)
		if got := f.os.callsMatching("share 4 9"); got != 1 {
			t.Errorf("shared the Wi-Fi %d times: %v", got, f.os.calls)
		}
	})
}

func TestHotspotSharingFollowsTheTunnel(t *testing.T) {
	for _, block := range []bool{true, false} {
		t.Run(fmt.Sprintf("block=%t", block), func(t *testing.T) {
			f := newHotspotFixture(t)
			if block {
				f.allow()
			} else {
				f.allow(testWiFi)
			}
			f.set(true, block)

			// While the tunnel comes up, what was shared stays and forwards nothing.
			shared := hotspotSharedWiFi
			if block {
				shared = hotspotSharedNone
			}
			f.allow()
			f.engineEvent(EngineConnecting)
			f.wantState(shared, true, testWiFi, false)

			f.allow(testTunnel)
			f.engineEvent(EngineConnected)
			f.wantState(hotspotSharedTunnel, false, testTunnel, true)

			f.allow()
			f.engineEvent(EngineDisconnecting)
			f.wantState(hotspotSharedTunnel, true, testTunnel, false)

			if !block {
				f.allow(testWiFi)
			}
			f.engineEvent(EngineDisconnected)
			if block {
				f.wantState(hotspotSharedTunnel, true, testTunnel, false)
			} else {
				f.wantState(hotspotSharedWiFi, false, testWiFi, true)
			}
		})
	}
}

// A hotspot turned on while the VPN is up shares the tunnel at once.
func TestHotspotSharingStartedWithTunnelUpSharesTheTunnel(t *testing.T) {
	f := newHotspotFixtureAt(t, tunnelUp)
	f.os.tunnel = testTunnel
	f.os.present[testTunnel] = true
	f.allow(testTunnel)
	f.set(true, true)
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)
	if got := f.os.callsMatching("share 7 9"); got != 1 {
		t.Errorf("shared the tunnel %d times: %v", got, f.os.calls)
	}
}

func TestHotspotSharingSharesAgainAfterEveryTunnelUp(t *testing.T) {
	f := newHotspotFixture(t)
	f.allow()
	f.set(true, true)
	f.allow(testTunnel)
	f.engineEvent(EngineConnected)
	f.allow()
	f.engineEvent(EngineDisconnecting)
	f.engineEvent(EngineDisconnected)
	f.engineEvent(EngineConnecting)
	f.allow(testTunnel)
	f.engineEvent(EngineConnected)
	if got := f.os.callsMatching("share 7 9"); got != 2 {
		t.Errorf("shared the tunnel %d times over two tunnel-ups, want 2: %v", got, f.os.calls)
	}
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)

	// An attach that replays "connected" is not a new tunnel-up.
	f.engineEvent(EngineAlreadyRunning)
	f.engineEvent(EngineConnected)
	if got := f.os.callsMatching("share 7 9"); got != 2 {
		t.Errorf("a replayed connected event shared again: %v", f.os.calls)
	}
}

func TestHotspotSharingBlockSurvivesAnotherStart(t *testing.T) {
	f := newHotspotFixture(t)
	f.allow()
	f.set(true, true)
	f.allow(testTunnel)
	f.engineEvent(EngineConnected)
	f.allow()
	f.engineEvent(EngineDisconnecting)
	f.engineEvent(EngineDisconnected)
	f.wantState(hotspotSharedTunnel, true, testTunnel, false)

	// The plugin starts the hotspot again, and ICS turns forwarding on with it.
	f.os.forwarding[testHotspot] = true
	f.sharing.reconcile()
	f.wantState(hotspotSharedTunnel, true, testTunnel, false)
}

func TestHotspotSharingConnectErrorWithBlockStaysBlocked(t *testing.T) {
	f := newHotspotFixture(t)
	f.allow()
	f.set(true, true)
	f.engineEvent(EngineConnecting)
	f.engineEvent(EngineError)
	f.wantState(hotspotSharedNone, true, testWiFi, false)
	f.allow(testTunnel)
	f.engineEvent(EngineConnected)
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)
}

func TestHotspotSharingConnectFailureWithoutBlockGoesDirect(t *testing.T) {
	f := newHotspotFixture(t)
	f.allow(testWiFi)
	f.set(true, false)
	f.allow()
	f.engineEvent(EngineConnecting)
	f.wantState(hotspotSharedWiFi, true, testWiFi, false)
	f.allow(testWiFi)
	f.engineEvent(EngineError)
	f.wantState(hotspotSharedWiFi, false, testWiFi, true)
}

// The Wi-Fi is shared after the tunnel is gone, not when the engine begins to
// stop, and a failed stop with the adapter still there is not down.
func TestHotspotSharingSharesTheWiFiOnlyAfterTheTunnelIsGone(t *testing.T) {
	f := newHotspotFixture(t)
	f.allow(testWiFi)
	f.set(true, false)
	sharedAtStart := f.os.callsMatching("share 4 9")
	f.allow(testTunnel)
	f.engineEvent(EngineConnected)

	f.allow()
	f.engineEvent(EngineDisconnecting)
	if got := f.os.callsMatching("share 4 9"); got != sharedAtStart {
		t.Errorf("shared the Wi-Fi at Disconnecting: %v", f.os.calls)
	}
	f.wantState(hotspotSharedTunnel, true, testTunnel, false)

	f.engineEvent(EngineError) // "Failed to stop", adapter still present
	if got := f.os.callsMatching("share 4 9"); got != sharedAtStart {
		t.Errorf("a failed stop with the adapter present counted as down: %v", f.os.calls)
	}
	f.wantState(hotspotSharedTunnel, true, testTunnel, false)

	f.allow(testWiFi)
	f.engineEvent(EngineDisconnected)
	f.wantState(hotspotSharedWiFi, false, testWiFi, true)
	if got := f.os.callsMatching("share 4 9"); got != sharedAtStart+1 {
		t.Errorf("shared the Wi-Fi %d times, want %d: %v", got, sharedAtStart+1, f.os.calls)
	}
}

// Proxy mode is told by the session, not by a missing adapter.
func TestHotspotSharingProxyModeIsAlwaysDown(t *testing.T) {
	for _, block := range []bool{true, false} {
		t.Run(fmt.Sprintf("block=%t", block), func(t *testing.T) {
			f := newHotspotFixtureAt(t, tunnelUp)
			f.sharing.proxySession = func() bool { return true }
			if block {
				f.allow()
			} else {
				f.allow(testWiFi)
			}
			f.set(true, block)
			if block {
				f.wantState(hotspotSharedNone, true, testWiFi, false)
				if f.os.callsMatching("share") != 0 {
					t.Errorf("shared without a tunnel and with the block on: %v", f.os.calls)
				}
			} else {
				f.wantState(hotspotSharedWiFi, false, testWiFi, true)
				if f.os.callsMatching("share 7") != 0 {
					t.Errorf("shared a tunnel there is none of: %v", f.os.calls)
				}
			}
		})
	}
}

// A session that says it is up with no adapter is not proxy mode: nothing is
// forwarded until the adapter is there.
func TestHotspotSharingUpWithoutAdapterForwardsNothing(t *testing.T) {
	f := newHotspotFixtureAt(t, tunnelUp)
	f.allow()
	f.set(true, false)
	f.wantState(hotspotSharedNone, true, testWiFi, false)
	if f.os.callsMatching("share") != 0 {
		t.Errorf("shared without an adapter: %v", f.os.calls)
	}
}

func TestHotspotSharingUsesTheRememberedConnectionWhenTunnelGoes(t *testing.T) {
	f := newHotspotFixture(t)
	f.allow(testWiFi)
	f.set(true, false)
	f.allow(testTunnel)
	f.engineEvent(EngineConnected)
	// The PC's own connection ranks differently while the hotspot rides the tunnel.
	f.os.physical = testLAN
	f.allow()
	f.engineEvent(EngineDisconnecting)
	f.allow(testWiFi)
	f.engineEvent(EngineDisconnected)
	f.wantState(hotspotSharedWiFi, false, testWiFi, true)

	// A core that never shared the Wi-Fi asks the OS.
	g := newHotspotFixture(t)
	g.os.public = testTunnel
	g.os.tunnel = testTunnel
	g.os.present[testTunnel] = true
	g.allow()
	g.set(true, false)
	g.os.tunnel = 0
	delete(g.os.present, testTunnel)
	g.allow(testWiFi)
	g.sharing.reconcile()
	g.wantState(hotspotSharedWiFi, false, testWiFi, true)
}

// A remembered connection that has gone is not shared again.
func TestHotspotSharingRechecksTheRememberedConnection(t *testing.T) {
	f := newHotspotFixture(t)
	f.allow(testWiFi)
	f.set(true, false)
	f.allow(testTunnel)
	f.engineEvent(EngineConnected)
	f.allow()
	f.engineEvent(EngineDisconnecting)

	// The Wi-Fi went away and the PC is on the other connection now.
	delete(f.os.present, testWiFi)
	f.os.physical = testLAN
	f.allow(testLAN)
	f.engineEvent(EngineDisconnected)
	if got := f.os.callsMatching("share 4 9"); got != 1 {
		t.Errorf("shared the Wi-Fi that is gone again: %v", f.os.calls)
	}
	f.wantPair(testLAN, true)
}

// A Windows without the live-switch exports cannot share anything, so nothing
// is forwarded: the block stays and the error says why. No restart is asked
// for, since nothing could confirm the pair it gave.
func TestHotspotSharingWithoutExportsNeverForwards(t *testing.T) {
	f := newHotspotFixture(t)
	f.os.available = false
	f.allow()
	f.set(true, false)
	event := f.last()
	if !event.Blocked || event.Error == "" || event.RestartOn != "" || event.Shared != hotspotSharedNone {
		t.Errorf("event = %+v, want blocked, none, an error and no restart", event)
	}
	f.engineEvent(EngineConnected)
	event = f.last()
	if !event.Blocked || event.Error == "" || event.RestartOn != "" {
		t.Errorf("event = %+v, want blocked with an error and no restart", event)
	}
	if f.os.callsMatching("share") != 0 || f.os.callsMatching("unshare") != 0 {
		t.Errorf("called the unavailable exports: %v", f.os.calls)
	}

	// The plugin restarted the hotspot on the tunnel's profile, and whatever
	// ICS reports is a record any local user can write: nothing forwards.
	f.os.public = testTunnel
	f.os.forwarding[testHotspot] = true
	f.sharing.reconcile()
	f.wantPair(testTunnel, false)
	if event := f.last(); !event.Blocked {
		t.Errorf("event = %+v, want blocked", event)
	}
}

// With no exports and no readable pair the hotspot is still found, so the
// block still goes on from the first look.
func TestHotspotSharingWithoutExportsAndWithoutAPairStillBlocks(t *testing.T) {
	f := newHotspotFixtureAt(t, tunnelUp)
	f.os.available = false
	f.os.pairErr = errors.New("unreadable")
	f.os.tunnel = testTunnel
	f.os.present[testTunnel] = true
	f.allow()
	f.set(true, true)
	event := f.last()
	if !event.Blocked || event.Error == "" {
		t.Errorf("event = %+v, want blocked with an error", event)
	}
	if f.os.forwarding[testHotspot] {
		t.Error("forwarding stayed on")
	}
}

// What ICS reports is never needed to share, nor to block.
func TestHotspotSharingNeedsNoReadablePair(t *testing.T) {
	f := newHotspotFixtureAt(t, tunnelUp)
	f.os.pairErr = errors.New("unreadable")
	f.os.tunnel = testTunnel
	f.os.present[testTunnel] = true
	f.allow(testTunnel)
	f.set(true, true)
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)
}

// A refused share leaves forwarding off.
func TestHotspotSharingRefusedShareKeepsForwardingOff(t *testing.T) {
	f := newHotspotFixture(t)
	f.os.shareErr = errors.New("denied")
	f.allow()
	f.set(true, false)
	if event := f.last(); event.RestartOn != hotspotSharedWiFi || event.Error == "" || !event.Blocked {
		t.Errorf("event = %+v, want blocked, restartOn wifi with an error", event)
	}
	f.allow()
	f.engineEvent(EngineConnected)
	event := f.last()
	if event.RestartOn != hotspotSharedTunnel || event.Error == "" || !event.Blocked {
		t.Errorf("event = %+v, want blocked, restartOn tunnel with an error", event)
	}
	// ICS refused to move and was stopped for another try: nothing forwards.
	f.wantPair(math.MaxUint32, false)

	// The tunnel is gone, ICS still points at it, and the Wi-Fi is refused too.
	f.os.public, f.os.private = testTunnel, testHotspot
	f.os.forwarding[testHotspot] = true
	f.engineEvent(EngineDisconnecting)
	f.engineEvent(EngineDisconnected)
	if event := f.last(); event.RestartOn != hotspotSharedWiFi || !event.Blocked {
		t.Errorf("event = %+v, want blocked, restartOn wifi", event)
	}
	f.wantPair(math.MaxUint32, false)
}

func TestHotspotSharingStopsThePairBeforeSharingAgainWhenRefused(t *testing.T) {
	f := newHotspotFixture(t)
	f.allow(testWiFi)
	f.set(true, false)
	f.os.shareFails = 1
	f.allow(testTunnel)
	f.engineEvent(EngineConnected)
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)
	if got := f.os.callsMatching("unshare 4 9"); got != 1 {
		t.Errorf("unshare calls = %d: %v", got, f.os.calls)
	}
}

func TestHotspotSharingWaitsForTheHotspotsInterface(t *testing.T) {
	f := newHotspotFixture(t)
	f.os.hotspotUp = false
	f.os.public, f.os.private = math.MaxUint32, math.MaxUint32
	f.allow()
	f.set(true, true)
	f.engineEvent(EngineConnected)
	if event := f.last(); event.Shared != hotspotSharedNone || event.Blocked || event.Error != "" {
		t.Errorf("event = %+v, want none, not blocked and no error", event)
	}
	if f.os.callsMatching("share") != 0 || f.os.callsMatching("forwarding") != 0 {
		t.Errorf("acted without a hotspot: %v", f.os.calls)
	}

	f.os.hotspotUp = true
	f.os.public, f.os.private = testWiFi, testHotspot
	f.allow(testTunnel)
	f.sharing.reconcile()
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)
}

func TestHotspotSharingOffLeavesNoPairAndNoBlock(t *testing.T) {
	f := newHotspotFixture(t)
	f.allow()
	f.set(true, true, "192.168.137.20")
	f.allow(testTunnel)
	f.engineEvent(EngineConnected)
	f.allow()
	f.engineEvent(EngineDisconnecting)
	f.engineEvent(EngineDisconnected)
	f.os.allowed = nil
	f.set(false, true)

	if event := f.last(); event.Shared != hotspotSharedNone || event.Blocked || event.Error != "" {
		t.Errorf("event = %+v, want none, not blocked", event)
	}
	if validInterfaceIndex(f.os.public) || validInterfaceIndex(f.os.private) {
		t.Errorf("a pair is left: %d, %d", f.os.public, f.os.private)
	}
	if len(f.os.clients) != 0 {
		t.Errorf("client blocks left: %v", f.os.clients)
	}
	if !f.os.forwarding[testHotspot] {
		t.Error("forwarding on the hotspot's interface was not given back")
	}

	// A tunnel-up after off shares nothing.
	f.engineEvent(EngineConnected)
	f.sharing.reconcile()
	if validInterfaceIndex(f.os.public) {
		t.Errorf("an event after off shared again: %v", f.os.calls)
	}
}

// Off gives back the forwarding a block turned off, though nothing was ever
// shared.
func TestHotspotSharingOffGivesBackAForwardingItTurnedOff(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, true)
	if f.os.forwarding[testHotspot] {
		t.Fatal("the block did not turn forwarding off")
	}
	f.set(false, true)
	if !f.os.forwarding[testHotspot] {
		t.Error("forwarding on the hotspot's interface was not given back")
	}
	if f.os.callsMatching("share") != 0 || f.os.callsMatching("unshare") != 0 {
		t.Errorf("a pair nobody shared was touched: %v", f.os.calls)
	}
}

// Off on a fresh core stops what an earlier run left, and only that.
func TestHotspotSharingOffOnAFreshCore(t *testing.T) {
	for name, tc := range map[string]struct {
		public  uint32
		tunnel  uint32
		stopped bool
	}{
		"pair on the tunnel":       {public: testTunnel, tunnel: testTunnel, stopped: true},
		"pair on a gone adapter":   {public: testGoneIndex, stopped: true},
		"pair on a physical":       {public: testWiFi, stopped: false},
		"pair with no public side": {public: math.MaxUint32, stopped: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newHotspotFixture(t)
			f.os.public = tc.public
			f.os.tunnel = tc.tunnel
			if tc.tunnel != 0 {
				f.os.present[tc.tunnel] = true
			}
			f.os.forwarding[testHotspot] = false
			f.set(false, true)
			if event := f.last(); event.Shared != hotspotSharedNone || event.Error != "" {
				t.Errorf("event = %+v", event)
			}
			unshared := f.os.callsMatching("unshare") == 1
			if unshared != tc.stopped {
				t.Errorf("pair stopped = %t, want %t: %v", unshared, tc.stopped, f.os.calls)
			}
			if tc.stopped && !f.os.forwarding[testHotspot] {
				t.Error("forwarding was not turned back on")
			}
			if !tc.stopped && (f.os.callsMatching("forwarding") != 0 || f.os.public != tc.public) {
				t.Errorf("touched the user's own hotspot: %v", f.os.calls)
			}
		})
	}
}

func TestHotspotSharingBlockedClients(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, false, "192.168.137.30", "192.168.137.20", "192.168.137.30")
	want := []netip.Addr{netip.MustParseAddr("192.168.137.20"), netip.MustParseAddr("192.168.137.30")}
	if !slices.Equal(f.os.clients, want) {
		t.Errorf("blocked = %v, want %v", f.os.clients, want)
	}
	f.sharing.reconcile()
	f.set(true, false, "192.168.137.30", "192.168.137.20")
	if got := f.os.callsMatching("clients"); got != 1 {
		t.Errorf("the same set was applied %d times", got)
	}
	f.set(true, false)
	if len(f.os.clients) != 0 {
		t.Errorf("unblocked clients are still blocked: %v", f.os.clients)
	}

	for _, bad := range []string{"fe80::1", "not an address", ""} {
		err := f.sharing.set(hotspotSharingRequest{On: true, BlockedClients: []string{bad}})
		if err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestParseBlockedClientsCapsAndDeduplicates(t *testing.T) {
	var eight []string
	for i := 1; i <= maxBlockedClients; i++ {
		eight = append(eight, fmt.Sprintf("192.168.137.%d", i))
	}
	if got, err := parseBlockedClients(eight); err != nil || len(got) != maxBlockedClients {
		t.Errorf("%d addresses: %v, %v", maxBlockedClients, got, err)
	}
	if _, err := parseBlockedClients(append(eight, "192.168.137.99")); err == nil {
		t.Errorf("more than %d addresses were accepted", maxBlockedClients)
	}
	got, err := parseBlockedClients([]string{"10.0.0.2", "10.0.0.2", " 10.0.0.1 "})
	if err != nil || len(got) != 2 || got[0] != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("parse = %v, %v", got, err)
	}
}

func TestHotspotSharingPublishesChangesAndAnswersASet(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, true)
	count := len(f.events)
	f.sharing.reconcile()
	if len(f.events) != count {
		t.Errorf("an unchanged state was published again")
	}
	f.set(true, true)
	if len(f.events) != count+1 {
		t.Errorf("a set did not answer with the state")
	}
	if f.sharing.lastPublished() == "" {
		t.Error("no state to replay")
	}
}

// The worker and its ticker live while sharing is on.
func TestHotspotSharingWorkerEndsWithOff(t *testing.T) {
	f := newHotspotFixture(t)
	f.sharing.useWorker(hotspotReconcileEvery)
	t.Cleanup(f.sharing.close)
	isRunning := func() (bool, chan struct{}) {
		f.sharing.mu.Lock()
		defer f.sharing.mu.Unlock()
		return f.sharing.running, f.sharing.done
	}
	f.set(true, false)
	running, done := isRunning()
	if !running {
		t.Fatal("no worker while sharing is on")
	}
	f.set(false, false)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the worker did not end after off")
	}
	if running, _ := isRunning(); running {
		t.Error("the worker outlived on:false")
	}
	f.set(true, false)
	if running, _ := isRunning(); !running {
		t.Error("the worker did not come back with on:true")
	}
}

// gatedHotspotOS holds the hotspot lookup, the first call a reconcile makes,
// until released.
type gatedHotspotOS struct {
	*fakeHotspotOS
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gatedHotspotOS) HotspotAdapters() ([]uint32, error) {
	g.once.Do(func() {
		close(g.entered)
		<-g.release
	})
	return g.fakeHotspotOS.HotspotAdapters()
}

// A caller of set holds a lock of its own (the service's pipe, the FFI call),
// so it must not wait behind a reconcile that is under way, nor the replay of
// the last event.
func TestHotspotSharingSetDoesNotWaitForAReconcile(t *testing.T) {
	gated := &gatedHotspotOS{fakeHotspotOS: newFakeHotspotOS(), entered: make(chan struct{}), release: make(chan struct{})}
	var mu sync.Mutex
	var payloads []string
	sharing := newHotspotSharing(gated, func(payload string) {
		mu.Lock()
		payloads = append(payloads, payload)
		mu.Unlock()
	}, tunnelDown)
	sharing.useWorker(0)
	t.Cleanup(sharing.close)

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		if err := sharing.set(hotspotSharingRequest{On: true, BlockWhileTunnelDown: true}); err != nil {
			t.Error(err)
		}
		<-gated.entered
		// The worker is inside a reconcile now.
		if err := sharing.set(hotspotSharingRequest{On: true}); err != nil {
			t.Error(err)
		}
		sharing.lastPublished()
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		close(gated.release)
		t.Fatal("set or lastPublished waited for the reconcile")
	}
	close(gated.release)

	// The state handed over last is the one applied.
	deadline := time.After(5 * time.Second)
	for {
		published := sharing.lastPublished()
		gated.fakeHotspotOS.mu.Lock()
		forwarding := gated.fakeHotspotOS.forwarding[testHotspot]
		gated.fakeHotspotOS.mu.Unlock()
		if published != "" && forwarding {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("the state handed over last was not applied: %q", published)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestTunnelPhaseOf(t *testing.T) {
	for code, want := range map[int32]tunnelPhase{
		EngineConnecting:     tunnelConnecting,
		EngineConnected:      tunnelUp,
		EngineAlreadyRunning: tunnelUp,
		EngineError:          tunnelDown,
		EngineDisconnecting:  tunnelDown,
		EngineDisconnected:   tunnelDown,
	} {
		if got, ok := tunnelPhaseOf(code); !ok || got != want {
			t.Errorf("tunnelPhaseOf(%d) = %v, %t, want %v", code, got, ok, want)
		}
	}
	for _, code := range []int32{StatsEvent, ServerEvent, LogEvent, EngineConflictOtherCore, EngineStopRejectedNotRunning, HotspotSharingEvent} {
		if _, ok := tunnelPhaseOf(code); ok {
			t.Errorf("code %d changes the tunnel's phase", code)
		}
	}
}
