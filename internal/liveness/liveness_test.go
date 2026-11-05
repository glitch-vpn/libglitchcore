package liveness

import (
	"testing"
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
