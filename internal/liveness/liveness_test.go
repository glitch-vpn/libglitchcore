package liveness

import (
	"testing"
	"time"
)

func TestTracker_UpImmediatelyDownDebounced(t *testing.T) {
	var tr Tracker
	if tr.State() != StateUnknown {
		t.Fatalf("zero state = %v, want unknown", tr.State())
	}

	// One failure from unknown is not conclusive.
	if st, changed := tr.ObserveFailure(); st != StateUnknown || changed {
		t.Fatalf("first failure -> %v changed=%v, want unknown/false", st, changed)
	}
	// The second consecutive failure flips down.
	if st, changed := tr.ObserveFailure(); st != StateDown || !changed {
		t.Fatalf("second failure -> %v changed=%v, want down/true", st, changed)
	}
	// Repeated failures don't re-signal.
	if _, changed := tr.ObserveFailure(); changed {
		t.Fatal("repeat failure must not signal a change")
	}
	// A single success flips up immediately.
	if st, changed := tr.ObserveSuccess(); st != StateUp || !changed {
		t.Fatalf("success -> %v changed=%v, want up/true", st, changed)
	}
	// One failure while up keeps up (debounce), the next flips down.
	if st, changed := tr.ObserveFailure(); st != StateUp || changed {
		t.Fatalf("single failure while up -> %v changed=%v, want up/false", st, changed)
	}
	if st, _ := tr.ObserveFailure(); st != StateDown {
		t.Fatalf("second failure while up -> %v, want down", st)
	}
}

func TestTracker_ObserveWG(t *testing.T) {
	var tr Tracker

	// Fully idle: inconclusive, keeps unknown.
	if st, changed := tr.ObserveWG(WGSample{}); st != StateUnknown || changed {
		t.Fatalf("idle -> %v changed=%v, want unknown/false", st, changed)
	}
	// Rx progress -> tunnel is up.
	if st, _ := tr.ObserveWG(WGSample{RxDelta: 100}); st != StateUp {
		t.Fatalf("rx delta -> %v, want up", st)
	}
	// Fresh handshake alone keeps it up.
	if st, _ := tr.ObserveWG(WGSample{HasHandshake: true, HandshakeAge: time.Minute}); st != StateUp {
		t.Fatalf("fresh handshake -> %v, want up", st)
	}
	// Tx-without-rx on a stale handshake: two in a row flip down.
	stale := WGSample{TxDelta: 50, HasHandshake: true, HandshakeAge: 10 * time.Minute}
	tr.ObserveWG(stale)
	if st, _ := tr.ObserveWG(stale); st != StateDown {
		t.Fatalf("stale tx-only ×2 -> %v, want down", st)
	}
	// Idle after down must not resurrect the link.
	if st, changed := tr.ObserveWG(WGSample{}); st != StateDown || changed {
		t.Fatalf("idle after down -> %v changed=%v, want down/false", st, changed)
	}
	// Rx recovers immediately.
	if st, _ := tr.ObserveWG(WGSample{RxDelta: 1}); st != StateUp {
		t.Fatalf("rx after down -> %v, want up", st)
	}
}
