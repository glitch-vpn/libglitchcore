package core

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// The pair ICS reports comes from a record any local user can write. Nothing
// the order does depends on it being true: forwarding on the hotspot's
// interface follows what the order shared itself, and the interface it acts on
// is the hotspot's own adapter, found by its driver.

// touches says whether a call of the fake's log names the interface.
func touches(calls []string, index uint32) bool {
	for _, call := range calls {
		fields := strings.Fields(call)
		if len(fields) == 0 || (fields[0] != "share" && fields[0] != "unshare" && fields[0] != "forwarding") {
			continue
		}
		for _, field := range fields[1:] {
			if field == strconv.FormatUint(uint64(index), 10) {
				return true
			}
		}
	}
	return false
}

// A report that ICS shares the tunnel, while it really shares the Wi-Fi, does
// not leave forwarding on: the order shares the tunnel itself, and when that is
// refused or impossible the hotspot stays blocked.
func TestHotspotSharingForgedPublicSideNeverForwards(t *testing.T) {
	for name, tc := range map[string]struct {
		configure   func(*fakeHotspotOS)
		wantAttempt bool // the report did not excuse a share
	}{
		"share refused": {configure: func(os *fakeHotspotOS) { os.shareErr = errors.New("denied") }, wantAttempt: true},
		"no exports":    {configure: func(os *fakeHotspotOS) { os.available = false }},
	} {
		t.Run(name, func(t *testing.T) {
			f := newHotspotFixtureAt(t, tunnelUp)
			f.os.tunnel = testTunnel
			f.os.present[testTunnel] = true
			f.os.forged = &[2]uint32{testTunnel, testHotspot}
			tc.configure(f.os)
			f.allow()
			f.set(true, true)

			event := f.last()
			if !event.Blocked || event.Error == "" || event.Shared != hotspotSharedNone {
				t.Errorf("event = %+v, want blocked, none and an error: the tunnel is not shared on a forged record", event)
			}
			if f.os.forwarding[testHotspot] {
				t.Error("forwarding stayed on with ICS really on the Wi-Fi")
			}
			if attempted := f.os.callsMatching("share 7 9") > 0; attempted != tc.wantAttempt {
				t.Errorf("share attempted = %t, want %t: %v", attempted, tc.wantAttempt, f.os.calls)
			}
		})
	}
}

// A private side that is another connection of the PC is not the hotspot's
// adapter: no share, stop or forwarding is aimed at it.
func TestHotspotSharingForgedPrivateSideIsNeverActedOn(t *testing.T) {
	f := newHotspotFixtureAt(t, tunnelUp)
	f.os.tunnel = testTunnel
	f.os.present[testTunnel] = true
	f.os.forged = &[2]uint32{testWiFi, testLAN}
	f.os.shareFails = 1
	f.allow(testTunnel)
	f.set(true, true)

	f.engineEvent(EngineDisconnecting)
	f.engineEvent(EngineDisconnected)
	f.allow(testTunnel, testWiFi)
	f.set(true, false)
	f.set(false, false)

	if touches(f.os.calls, testLAN) {
		t.Errorf("acted on the other connection: %v", f.os.calls)
	}
	if f.os.forwarding[testLAN] {
		t.Error("forwarding was turned on for another connection")
	}
}

// The same on a fresh core's off, which stops a pair an earlier run left: the
// pair is stopped only where ICS's private side is the hotspot's adapter.
func TestHotspotSharingOffIgnoresAForgedPrivateSide(t *testing.T) {
	f := newHotspotFixture(t)
	f.os.forged = &[2]uint32{testGoneIndex, testLAN}
	f.os.forwarding[testHotspot] = false
	f.set(false, true)

	if f.os.callsMatching("unshare") != 0 || f.os.callsMatching("forwarding") != 0 {
		t.Errorf("acted on a private side that is not the hotspot's adapter: %v", f.os.calls)
	}
	if f.os.public != testWiFi || f.os.private != testHotspot {
		t.Errorf("the user's own pair was stopped: %d, %d", f.os.public, f.os.private)
	}
}

// A refused share stops the standing pair only where the report names the
// hotspot's adapter as its private side.
func TestHotspotSharingRefusedShareStopsOnlyThePairOfTheHotspot(t *testing.T) {
	f := newHotspotFixtureAt(t, tunnelUp)
	f.os.tunnel = testTunnel
	f.os.present[testTunnel] = true
	f.os.forged = &[2]uint32{testWiFi, testLAN}
	f.os.shareFails = 1
	f.allow()
	f.set(true, true)
	if f.os.callsMatching("unshare") != 0 {
		t.Errorf("stopped a pair on a private side that is not the hotspot's: %v", f.os.calls)
	}
	if event := f.last(); !event.Blocked || event.Shared != hotspotSharedNone || event.Error == "" {
		t.Errorf("event = %+v, want blocked, none and an error", event)
	}
}

// A hotspot restarted by anyone is shared again: the order does not take a
// report that ICS is on the connection it wants for the share it made.
func TestHotspotSharingSharesAgainWhenTheHotspotAdapterComesBack(t *testing.T) {
	f := newHotspotFixtureAt(t, tunnelUp)
	f.os.tunnel = testTunnel
	f.os.present[testTunnel] = true
	f.allow(testTunnel)
	f.set(true, true)
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)

	// The hotspot goes away and comes back on the Wi-Fi, with forwarding on, as
	// Windows starts it; whatever is written in the record says the tunnel.
	f.os.hotspotUp = false
	f.sharing.reconcile()
	f.os.hotspotUp = true
	f.os.public, f.os.private = testWiFi, testHotspot
	f.os.forwarding[testHotspot] = true
	f.os.forged = &[2]uint32{testTunnel, testHotspot}
	f.os.shareErr = errors.New("denied")
	f.allow()
	f.sharing.reconcile()

	if got := f.os.callsMatching("share 7 9"); got != 2 {
		t.Errorf("shared the tunnel %d times, want once more after the restart: %v", got, f.os.calls)
	}
	if f.os.forwarding[testHotspot] {
		t.Error("forwarding stayed on for a hotspot restarted on the Wi-Fi")
	}
	if event := f.last(); !event.Blocked || event.Shared == hotspotSharedTunnel {
		t.Errorf("event = %+v, want blocked and not the tunnel", event)
	}
}

// ICS moved by someone else with the adapter staying up between two checks:
// the report, believed only for the worse, takes the share away, and the order
// shares again.
func TestHotspotSharingSharesAgainWhenICSReportsAnotherPair(t *testing.T) {
	f := newHotspotFixtureAt(t, tunnelUp)
	f.os.tunnel = testTunnel
	f.os.present[testTunnel] = true
	f.allow(testTunnel)
	f.set(true, true)
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)

	f.os.public = testWiFi
	f.os.shareErr = errors.New("denied")
	f.allow()
	f.sharing.reconcile()
	if f.os.forwarding[testHotspot] {
		t.Error("forwarding stayed on while ICS shares the Wi-Fi")
	}
	if event := f.last(); !event.Blocked || event.Shared != hotspotSharedNone {
		t.Errorf("event = %+v, want blocked and none", event)
	}

	f.os.shareErr = nil
	f.allow(testTunnel)
	f.sharing.reconcile()
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)
}

// A report can take a share away and never give one: whatever it says, a
// reconcile with no record never forwards.
func TestHotspotSharingAReportNeverRestoresARecord(t *testing.T) {
	f := newHotspotFixtureAt(t, tunnelUp)
	f.os.tunnel = testTunnel
	f.os.present[testTunnel] = true
	f.allow(testTunnel)
	f.set(true, true)

	f.os.hotspotUp = false
	f.sharing.reconcile()
	f.os.hotspotUp = true
	f.os.public, f.os.private = testWiFi, testHotspot
	f.os.forwarding[testHotspot] = true
	f.os.forged = &[2]uint32{testTunnel, testHotspot}
	f.os.available = false
	f.allow()
	f.sharing.reconcile()
	if f.os.forwarding[testHotspot] {
		t.Error("a report of the wanted pair turned forwarding on")
	}
}

// The adapter that came back may not be the one that went: the share is of the
// adapter that is there now.
func TestHotspotSharingFollowsTheHotspotAdapterToAnotherIndex(t *testing.T) {
	const other = 11
	f := newHotspotFixtureAt(t, tunnelUp)
	f.os.tunnel = testTunnel
	f.os.present[testTunnel] = true
	f.allow(testTunnel)
	f.set(true, true)

	f.os.hotspot = other
	f.os.present[other] = true
	f.os.public, f.os.private = testWiFi, other
	f.os.forwarding[other] = true
	f.sharing.reconcile()
	if got := f.os.callsMatching("share 7 11"); got != 1 {
		t.Errorf("did not share with the adapter that is there now: %v", f.os.calls)
	}
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)
	if !f.os.forwarding[other] {
		t.Error("forwarding is off on the adapter that was shared")
	}
}

// Every request shares again, since the plugin sends one right after each start
// and ICS has turned forwarding on with it.
func TestHotspotSharingSharesAgainOnEverySet(t *testing.T) {
	f := newHotspotFixtureAt(t, tunnelUp)
	f.os.tunnel = testTunnel
	f.os.present[testTunnel] = true
	f.allow(testTunnel)
	for want := 1; want <= 3; want++ {
		f.set(true, true)
		if got := f.os.callsMatching("share 7 9"); got != want {
			t.Errorf("after %d requests the tunnel was shared %d times: %v", want, got, f.os.calls)
		}
	}
	f.sharing.reconcile()
	if got := f.os.callsMatching("share 7 9"); got != 3 {
		t.Errorf("a check shared again: %v", f.os.calls)
	}
}

// With the adapters unlisted nothing is shared or changed on a guess, and an
// adapter this order knew has forwarding turned off.
func TestHotspotSharingActsOnNothingWhenTheHotspotAdapterIsUnknown(t *testing.T) {
	f := newHotspotFixtureAt(t, tunnelUp)
	f.os.tunnel = testTunnel
	f.os.present[testTunnel] = true
	f.os.hotspotErr = errors.New("cannot list adapters")
	f.allow()
	f.set(true, true)
	if event := f.last(); event.Shared != hotspotSharedNone || event.Error == "" {
		t.Errorf("event = %+v, want none with an error", event)
	}
	if f.os.callsMatching("share") != 0 || f.os.callsMatching("forwarding") != 0 || f.os.callsMatching("unshare") != 0 {
		t.Errorf("acted without knowing the hotspot adapter: %v", f.os.calls)
	}

	// Known first, then lost: forwarding goes off on the adapter it was.
	g := newHotspotFixtureAt(t, tunnelUp)
	g.os.tunnel = testTunnel
	g.os.present[testTunnel] = true
	g.allow(testTunnel)
	g.set(true, true)
	g.wantState(hotspotSharedTunnel, false, testTunnel, true)
	g.os.hotspotErr = errors.New("cannot list adapters")
	g.allow()
	g.sharing.reconcile()
	if g.os.forwarding[testHotspot] {
		t.Error("forwarding stayed on with the hotspot's adapter unknown")
	}
	if event := g.last(); event.Error == "" || event.Shared != hotspotSharedNone {
		t.Errorf("event = %+v, want none with an error", event)
	}
}

// With two Wi-Fi Direct adapters up (a hotspot beside a wireless display) it
// cannot be told which is the hotspot's: nothing is shared, and forwarding is
// off on both.
func TestHotspotSharingWithTwoWiFiDirectAdaptersUpBlocksBothAndSharesNothing(t *testing.T) {
	const cast = 11
	f := newHotspotFixtureAt(t, tunnelUp)
	f.os.tunnel = testTunnel
	f.os.present[testTunnel] = true
	f.os.otherWFD = []uint32{cast}
	f.os.forwarding[cast] = true
	f.allow()
	f.set(true, true)

	if f.os.forwarding[testHotspot] || f.os.forwarding[cast] {
		t.Errorf("forwarding stayed on: hotspot %t, other %t", f.os.forwarding[testHotspot], f.os.forwarding[cast])
	}
	if f.os.callsMatching("share") != 0 || f.os.callsMatching("unshare") != 0 {
		t.Errorf("shared on a guess: %v", f.os.calls)
	}
	if event := f.last(); event.Shared != hotspotSharedNone || event.Error == "" {
		t.Errorf("event = %+v, want none with an error", event)
	}

	// The wireless display ends: the hotspot is the one adapter and is shared.
	f.os.otherWFD = nil
	f.allow(testTunnel)
	f.sharing.reconcile()
	f.wantState(hotspotSharedTunnel, false, testTunnel, true)
}

// A request that turned sharing on while the order was ending an earlier off
// keeps its flags: the off does not clear what it never read.
func TestHotspotSharingOffKeepsTheFlagsOfALaterOn(t *testing.T) {
	f := newHotspotFixture(t)
	f.sharing.mu.Lock()
	f.sharing.request = hotspotSharingRequest{On: true}
	f.sharing.active, f.sharing.shareAgain = true, true
	f.sharing.mu.Unlock()
	f.sharing.tearDown(true)
	f.sharing.mu.Lock()
	defer f.sharing.mu.Unlock()
	if !f.sharing.active || !f.sharing.shareAgain {
		t.Errorf("an off cleared the flags of the on that came after it: active %t, shareAgain %t", f.sharing.active, f.sharing.shareAgain)
	}
}
