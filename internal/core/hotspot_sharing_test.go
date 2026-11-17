package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sync"
	"testing"
)

const (
	testWiFi    = 4
	testTunnel  = 7
	testHotspot = 9
)

// fakeHotspotOS behaves as ICS does: a share sets the pair and turns
// forwarding on for the private side.
type fakeHotspotOS struct {
	mu sync.Mutex

	available  bool
	public     uint32
	private    uint32
	tunnel     uint32 // 0: no adapter
	physical   uint32
	forwarding map[uint32]bool
	clients    []netip.Addr

	shareErr   error
	shareFails int // how many Share calls still fail
	calls      []string
}

func newFakeHotspotOS() *fakeHotspotOS {
	return &fakeHotspotOS{
		available:  true,
		public:     testWiFi,
		private:    testHotspot,
		physical:   testWiFi,
		forwarding: map[uint32]bool{testHotspot: true},
	}
}

func (f *fakeHotspotOS) record(format string, args ...any) {
	f.calls = append(f.calls, fmt.Sprintf(format, args...))
}

func (f *fakeHotspotOS) callsMatching(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	count := 0
	for _, call := range f.calls {
		if len(call) >= len(prefix) && call[:len(prefix)] == prefix {
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
	return nil
}

func (f *fakeHotspotOS) Unshare(public, private uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("unshare %d %d", public, private)
	f.public, f.private = math.MaxUint32, math.MaxUint32
	return nil
}

func (f *fakeHotspotOS) TunnelIndex() (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tunnel, f.tunnel != 0
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
	fixture := &hotspotFixture{t: t, os: newFakeHotspotOS()}
	fixture.sharing = newHotspotSharing(fixture.os, func(payload string) {
		var event hotspotSharingEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			t.Errorf("event %q is not JSON: %v", payload, err)
		}
		fixture.events = append(fixture.events, event)
	})
	return fixture
}

func (f *hotspotFixture) set(on, block bool, clients ...string) {
	f.t.Helper()
	if err := f.sharing.set(hotspotSharingRequest{On: on, BlockWhileTunnelDown: block, BlockedClients: clients}); err != nil {
		f.t.Fatalf("set: %v", err)
	}
}

// tunnelEvent sends the lifecycle event and applies it, as the worker does on
// its wake.
func (f *hotspotFixture) tunnelEvent(code int32) {
	f.t.Helper()
	if code == EngineConnected {
		f.os.mu.Lock()
		f.os.tunnel = testTunnel
		f.os.mu.Unlock()
	}
	f.sharing.notify(code)
	f.sharing.reconcile(false)
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
	if f.os.public != public {
		f.t.Errorf("ICS public = %d, want %d", f.os.public, public)
	}
	if f.os.forwarding[testHotspot] != forwarding {
		f.t.Errorf("forwarding on the hotspot = %t, want %t", f.os.forwarding[testHotspot], forwarding)
	}
}

func TestHotspotSharingStartedWithTunnelDown(t *testing.T) {
	for _, block := range []bool{true, false} {
		t.Run(fmt.Sprintf("block=%t", block), func(t *testing.T) {
			f := newHotspotFixture(t)
			f.set(true, block)
			// The hotspot starts on the Wi-Fi's profile with forwarding on; the block
			// goes on at once, and without it nothing is touched.
			f.wantState(hotspotSharedWiFi, block, testWiFi, !block)
			if f.os.callsMatching("share") != 0 {
				t.Errorf("shared with the tunnel down: %v", f.os.calls)
			}
		})
	}
}

func TestHotspotSharingFollowsTheTunnel(t *testing.T) {
	for _, block := range []bool{true, false} {
		t.Run(fmt.Sprintf("block=%t", block), func(t *testing.T) {
			f := newHotspotFixture(t)
			f.set(true, block)

			f.tunnelEvent(EngineConnecting)
			f.wantState(hotspotSharedWiFi, true, testWiFi, false)

			f.tunnelEvent(EngineConnected)
			f.wantState(hotspotSharedTunnel, false, testTunnel, true)

			f.tunnelEvent(EngineDisconnecting)
			f.tunnelEvent(EngineDisconnected)
			if block {
				// The pair stays on the tunnel and nothing is forwarded.
				f.wantState(hotspotSharedTunnel, true, testTunnel, false)
			} else {
				f.wantState(hotspotSharedWiFi, false, testWiFi, true)
			}
		})
	}
}

func TestHotspotSharingSharesAgainAfterEveryTunnelUp(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, true)
	f.tunnelEvent(EngineConnected)
	f.tunnelEvent(EngineDisconnected)
	f.tunnelEvent(EngineConnecting)
	f.tunnelEvent(EngineConnected)
	if got := f.os.callsMatching("share 7 9"); got != 2 {
		t.Errorf("shared the tunnel %d times over two tunnel-ups, want 2: %v", got, f.os.calls)
	}
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)

	// An attach that replays "connected" is not a new tunnel-up.
	f.tunnelEvent(EngineAlreadyRunning)
	f.tunnelEvent(EngineConnected)
	if got := f.os.callsMatching("share 7 9"); got != 2 {
		t.Errorf("a replayed connected event shared again: %v", f.os.calls)
	}
}

func TestHotspotSharingBlockSurvivesAnotherStart(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, true)
	f.tunnelEvent(EngineConnected)
	f.tunnelEvent(EngineDisconnected)
	f.wantState(hotspotSharedTunnel, true, testTunnel, false)

	// The plugin starts the hotspot again, and ICS turns forwarding on with it.
	f.os.forwarding[testHotspot] = true
	f.sharing.reconcile(false)
	f.wantState(hotspotSharedTunnel, true, testTunnel, false)
}

func TestHotspotSharingConnectErrorWithBlockStaysBlocked(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, true)
	f.tunnelEvent(EngineConnecting)
	f.os.calls = nil
	// A connect that ends in an error with the block on stays blocked, and the
	// share that follows a later tunnel-up lifts it.
	f.tunnelEvent(EngineError)
	f.wantState(hotspotSharedWiFi, true, testWiFi, false)
	f.tunnelEvent(EngineConnected)
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)
}

func TestHotspotSharingConnectFailureWithoutBlockGoesDirect(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, false)
	f.tunnelEvent(EngineConnecting)
	f.wantState(hotspotSharedWiFi, true, testWiFi, false)
	f.tunnelEvent(EngineError)
	f.wantState(hotspotSharedWiFi, false, testWiFi, true)
}

func TestHotspotSharingProxyModeIsAlwaysDown(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, true)
	// Connected with no adapter named GlitchVPN: a proxy-mode session.
	f.sharing.notify(EngineConnected)
	f.sharing.reconcile(false)
	f.wantState(hotspotSharedWiFi, true, testWiFi, false)
	if f.os.callsMatching("share") != 0 {
		t.Errorf("shared without a tunnel: %v", f.os.calls)
	}
}

func TestHotspotSharingUsesTheRememberedConnectionWhenTunnelGoes(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, false)
	f.tunnelEvent(EngineConnected)
	// The physical connection's index changed while the hotspot rode the tunnel.
	f.os.physical = 12
	f.tunnelEvent(EngineDisconnected)
	f.wantState(hotspotSharedWiFi, false, testWiFi, true)

	// A core that never saw the hotspot on the physical connection asks the OS.
	g := newHotspotFixture(t)
	g.os.public = testTunnel
	g.os.tunnel = testTunnel
	g.set(true, false)
	g.sharing.notify(EngineDisconnected)
	g.sharing.reconcile(false)
	g.wantState(hotspotSharedWiFi, false, testWiFi, true)
}

func TestHotspotSharingFallsBackWhenTheLiveSwitchIsUnavailable(t *testing.T) {
	f := newHotspotFixture(t)
	f.os.available = false
	f.set(true, false)
	f.tunnelEvent(EngineConnected)
	event := f.last()
	if event.RestartOn != hotspotSharedTunnel || event.Error == "" {
		t.Errorf("event = %+v, want restartOn tunnel with an error", event)
	}
	if f.os.callsMatching("share") != 0 || f.os.callsMatching("unshare") != 0 {
		t.Errorf("called the unavailable exports: %v", f.os.calls)
	}

	f.os.public = testTunnel
	f.tunnelEvent(EngineDisconnected)
	if event := f.last(); event.RestartOn != hotspotSharedWiFi {
		t.Errorf("event = %+v, want restartOn wifi", event)
	}
}

func TestHotspotSharingNoRestartOnceTheHotspotIsOnTheWantedConnection(t *testing.T) {
	f := newHotspotFixture(t)
	f.os.available = false
	f.set(true, false)
	f.tunnelEvent(EngineConnected)
	// The plugin restarted the hotspot on the tunnel's profile.
	f.os.public = testTunnel
	f.sharing.reconcile(false)
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)
}

func TestHotspotSharingStopsThePairBeforeSharingAgainWhenRefused(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, false)
	f.os.shareFails = 1
	f.tunnelEvent(EngineConnected)
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)
	if got := f.os.callsMatching("unshare 4 9"); got != 1 {
		t.Errorf("unshare calls = %d: %v", got, f.os.calls)
	}

	g := newHotspotFixture(t)
	g.os.shareErr = errors.New("denied")
	g.set(true, false)
	g.tunnelEvent(EngineConnected)
	if event := g.last(); event.RestartOn != hotspotSharedTunnel || event.Error == "" {
		t.Errorf("event = %+v, want restartOn tunnel with an error", event)
	}
}

func TestHotspotSharingWaitsForTheHotspotsInterface(t *testing.T) {
	f := newHotspotFixture(t)
	f.os.public, f.os.private = math.MaxUint32, math.MaxUint32
	f.set(true, true)
	f.tunnelEvent(EngineConnected)
	if event := f.last(); event.Shared != hotspotSharedNone || event.Blocked {
		t.Errorf("event = %+v, want none and not blocked", event)
	}
	if f.os.callsMatching("share") != 0 || f.os.callsMatching("forwarding") != 0 {
		t.Errorf("acted without a hotspot: %v", f.os.calls)
	}

	f.os.public, f.os.private = testWiFi, testHotspot
	f.sharing.reconcile(false)
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)
}

func TestHotspotSharingOffLeavesNoPairAndNoBlock(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, true, "192.168.137.20")
	f.tunnelEvent(EngineConnected)
	f.tunnelEvent(EngineDisconnected)
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

	before := len(f.os.calls)
	f.tunnelEvent(EngineConnected)
	f.sharing.reconcile(false)
	if len(f.os.calls) != before {
		t.Errorf("an event after off still acted: %v", f.os.calls[before:])
	}
}

func TestHotspotSharingOffTouchesNothingItNeverTurnedOn(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(false, false)
	if len(f.os.calls) != 0 {
		t.Errorf("a core that was never on acted: %v", f.os.calls)
	}
	if event := f.last(); event.Shared != hotspotSharedNone {
		t.Errorf("event = %+v", event)
	}
}

func TestHotspotSharingBlockedClients(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, false, "192.168.137.30", "192.168.137.20", "192.168.137.30")
	want := []netip.Addr{netip.MustParseAddr("192.168.137.20"), netip.MustParseAddr("192.168.137.30")}
	if !slices.Equal(f.os.clients, want) {
		t.Errorf("blocked = %v, want %v", f.os.clients, want)
	}
	f.sharing.reconcile(false)
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

func TestHotspotSharingPublishesChangesAndAnswersASet(t *testing.T) {
	f := newHotspotFixture(t)
	f.set(true, true)
	count := len(f.events)
	f.sharing.reconcile(false)
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
