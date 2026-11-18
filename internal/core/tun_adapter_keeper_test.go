package core

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// fakeKeptAdapter counts what the keeper does to the adapter it holds.
type fakeKeptAdapter struct {
	closed atomic.Int32
	lost   atomic.Bool
}

func (a *fakeKeptAdapter) Usable() bool { return !a.lost.Load() }

func (a *fakeKeptAdapter) Close() error {
	a.closed.Add(1)
	return nil
}

func TestAdapterKeeper_CreatesOnceInTheBackground(t *testing.T) {
	var gate adapterGate
	var creates atomic.Int32
	adapter := &fakeKeptAdapter{}
	started := time.Now()
	k := startAdapterKeeper(&gate, func() (keptAdapter, error) {
		creates.Add(1)
		time.Sleep(200 * time.Millisecond)
		return adapter, nil
	})
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("starting the keeper waited for the create")
	}
	<-k.done
	if creates.Load() != 1 || k.adapter == nil {
		t.Fatalf("creates = %d, adapter kept = %t; want one create and the adapter kept", creates.Load(), k.adapter != nil)
	}
	k.close()
	k.close()
	if adapter.closed.Load() != 1 {
		t.Fatalf("adapter closed %d times, want 1", adapter.closed.Load())
	}
}

func TestAdapterKeeper_AConnectWaitsForThePendingCreate(t *testing.T) {
	var gate adapterGate
	finish := make(chan struct{})
	var creates atomic.Int32
	k := startAdapterKeeper(&gate, func() (keptAdapter, error) {
		creates.Add(1)
		<-finish
		return &fakeKeptAdapter{}, nil
	})
	claimed := make(chan struct{})
	go func() {
		release, err := gate.claim(5 * time.Second)
		if err != nil {
			t.Errorf("claim: %v", err)
			return
		}
		defer release()
		close(claimed)
	}()
	select {
	case <-claimed:
		t.Fatal("a connect took the gate while the create was pending")
	case <-time.After(150 * time.Millisecond):
	}
	close(finish)
	select {
	case <-claimed:
	case <-time.After(5 * time.Second):
		t.Fatal("the connect did not proceed after the create returned")
	}
	if creates.Load() != 1 {
		t.Fatalf("creates = %d, want 1", creates.Load())
	}
	k.close()
}

func TestAdapterKeeper_AFailedCreateLeavesTheGateToTheSessions(t *testing.T) {
	var gate adapterGate
	k := startAdapterKeeper(&gate, func() (keptAdapter, error) { return nil, errors.New("refused") })
	<-k.done
	release, err := gate.claim(time.Second)
	if err != nil {
		t.Fatalf("the gate stayed held after a failed create: %v", err)
	}
	release()
	if k.adapter != nil {
		t.Fatal("an adapter is kept after a failed create")
	}
	k.close()
}

func TestAdapterKeeper_CloseDuringTheCreateRemovesTheAdapterOnceItExists(t *testing.T) {
	var gate adapterGate
	finish := make(chan struct{})
	adapter := &fakeKeptAdapter{}
	k := startAdapterKeeper(&gate, func() (keptAdapter, error) {
		<-finish
		return adapter, nil
	})
	closed := make(chan struct{})
	go func() {
		k.close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("close returned before the create did")
	case <-time.After(100 * time.Millisecond):
	}
	close(finish)
	<-closed
	if adapter.closed.Load() != 1 {
		t.Fatalf("adapter closed %d times, want 1", adapter.closed.Load())
	}
}

func TestAdapterKeeper_CloseWaitsForARunningSessionThenGoesAnyway(t *testing.T) {
	prev := desktopAdapterKeeperWait
	t.Cleanup(func() { desktopAdapterKeeperWait = prev })
	desktopAdapterKeeperWait = 100 * time.Millisecond
	var gate adapterGate
	adapter := &fakeKeptAdapter{}
	k := startAdapterKeeper(&gate, func() (keptAdapter, error) { return adapter, nil })
	<-k.done
	release, err := gate.claim(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	k.close()
	if adapter.closed.Load() != 1 {
		t.Fatalf("adapter closed %d times, want 1", adapter.closed.Load())
	}
}

// A core whose create failed because another process held the name gets the
// adapter at the next connect once that process is gone.
func TestAdapterKeeper_EnsureCreatesAgainAfterAFailedCreate(t *testing.T) {
	var gate adapterGate
	var creates atomic.Int32
	adapter := &fakeKeptAdapter{}
	k := startAdapterKeeper(&gate, func() (keptAdapter, error) {
		if creates.Add(1) == 1 {
			return nil, errors.New("held by another process")
		}
		return adapter, nil
	})
	<-k.done
	if err := k.ensure(); err != nil {
		t.Fatal(err)
	}
	if creates.Load() != 2 || k.adapter != adapter {
		t.Fatalf("creates = %d, adapter kept = %t; want a second create to keep it", creates.Load(), k.adapter == adapter)
	}
	k.ensure()
	if creates.Load() != 2 {
		t.Fatalf("ensure created again with a usable adapter held (%d creates)", creates.Load())
	}
	k.close()
}

// An adapter the user disabled or a network reset removed is replaced at the
// next connect, and its handle is closed first.
func TestAdapterKeeper_EnsureReplacesALostAdapter(t *testing.T) {
	var gate adapterGate
	var made []*fakeKeptAdapter
	k := startAdapterKeeper(&gate, func() (keptAdapter, error) {
		a := &fakeKeptAdapter{}
		made = append(made, a)
		return a, nil
	})
	<-k.done
	made[0].lost.Store(true)
	if err := k.ensure(); err != nil {
		t.Fatal(err)
	}
	if len(made) != 2 || made[0].closed.Load() != 1 || k.adapter != keptAdapter(made[1]) {
		t.Fatalf("%d created, lost one closed %d times; want 2, 1 and the new one kept", len(made), made[0].closed.Load())
	}
	k.close()
}

func TestAdapterKeeper_EnsureAfterCloseCreatesNothing(t *testing.T) {
	var gate adapterGate
	var creates atomic.Int32
	k := startAdapterKeeper(&gate, func() (keptAdapter, error) {
		creates.Add(1)
		return &fakeKeptAdapter{}, nil
	})
	k.close()
	if err := k.ensure(); err != nil {
		t.Fatal(err)
	}
	if creates.Load() != 1 {
		t.Fatalf("%d creates, want 1", creates.Load())
	}
}

// Both engines take the gate through claimDesktopAdapter, so each connect
// finds the adapter the keeper holds, or tries the create once more first.
func TestClaimDesktopAdapterEnsuresTheKeptAdapter(t *testing.T) {
	var creates atomic.Int32
	adapter := &fakeKeptAdapter{}
	k := startAdapterKeeper(&desktopAdapterGate, func() (keptAdapter, error) {
		if creates.Add(1) == 1 {
			return nil, errors.New("held by another process")
		}
		return adapter, nil
	})
	<-k.done
	desktopKeeper.Store(k)
	t.Cleanup(func() { desktopKeeper.Store(nil) })
	release, err := claimDesktopAdapter()
	if err != nil {
		t.Fatal(err)
	}
	release()
	if creates.Load() != 2 || k.adapter != adapter {
		t.Fatalf("creates = %d; want the connect to create the adapter once the other holder had gone", creates.Load())
	}
	k.close()
}

func TestAdapterKeeper_ANilKeeperClosesNothing(t *testing.T) {
	var k *adapterKeeper
	k.close()
	if err := k.ensure(); err != nil {
		t.Fatal(err)
	}
}

// A create that fails for any other reason leaves the connect to create its
// own adapter: only a held name stops it.
func TestClaimDesktopAdapterProceedsWhenTheCreateFailsForAnotherReason(t *testing.T) {
	k := startAdapterKeeper(&desktopAdapterGate, func() (keptAdapter, error) { return nil, errors.New("driver missing") })
	<-k.done
	desktopKeeper.Store(k)
	t.Cleanup(func() { desktopKeeper.Store(nil); k.close() })
	release, err := claimDesktopAdapter()
	if err != nil {
		t.Fatalf("a create that failed for another reason stopped the connect: %v", err)
	}
	release()
}

// While another process holds the name each connect fails with that reason
// and frees the gate, and the first one after it leaves gets the adapter.
func TestClaimDesktopAdapterFailsWhileAnotherProcessHoldsTheName(t *testing.T) {
	var creates atomic.Int32
	adapter := &fakeKeptAdapter{}
	k := startAdapterKeeper(&desktopAdapterGate, func() (keptAdapter, error) {
		if creates.Add(1) <= 2 {
			return nil, errAdapterHeld
		}
		return adapter, nil
	})
	<-k.done
	desktopKeeper.Store(k)
	t.Cleanup(func() { desktopKeeper.Store(nil); k.close() })
	if _, err := claimDesktopAdapter(); !errors.Is(err, errAdapterHeld) {
		t.Fatalf("err = %v; want the held reason", err)
	}
	release, err := claimDesktopAdapter()
	if err != nil {
		t.Fatalf("the connect after the other holder left: %v", err)
	}
	release()
	if k.adapter != adapter {
		t.Fatal("the adapter was not kept once the name was free")
	}
}
