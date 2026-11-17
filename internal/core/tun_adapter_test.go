package core

import (
	"testing"
	"time"
)

func TestAdapterGate_ClaimWaitsForTheHolderToRelease(t *testing.T) {
	var gate adapterGate
	release, err := gate.claim(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	claimed := make(chan struct{})
	go func() {
		next, err := gate.claim(5 * time.Second)
		if err == nil {
			next()
		}
		close(claimed)
	}()
	select {
	case <-claimed:
		t.Fatal("a second claim returned while the first was held")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	release()
	select {
	case <-claimed:
	case <-time.After(5 * time.Second):
		t.Fatal("the second claim did not return after the release")
	}
}

func TestAdapterGate_ClaimGivesUpAfterTheWait(t *testing.T) {
	var gate adapterGate
	release, err := gate.claim(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := gate.claim(50 * time.Millisecond); err == nil {
		t.Fatal("a claim on a held gate succeeded")
	}
}
