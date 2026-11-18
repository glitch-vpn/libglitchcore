package core

import (
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// desktopAdapterKeeperWait bounds how long closing the keeper waits for a
// session that still holds desktopAdapterGate.
var desktopAdapterKeeperWait = 5 * time.Second

// errAdapterHeld is why a connect stops when the desktop adapter's name is
// held by another process: the user reads it as the reason of the failed start.
var errAdapterHeld = errors.New("the Glitch VPN adapter is held by another process: stop the other Glitch VPN core (the GlitchVpnCore service or another running instance)")

// keptAdapter is the adapter the keeper holds. Usable is false once it was
// lost and could not be created again.
type keptAdapter interface {
	io.Closer
	Usable() bool
}

// adapterKeeper holds the desktop adapter for the life of the process.
// Creating and removing a Windows adapter takes seconds, so it is created once,
// off any connect's path, and a session only starts and ends on it. The create
// holds the gate, so a connect that arrives first waits for it and then finds
// the adapter, never a second create. A failed create leaves each connect to
// try it again under the gate before anything else; when another process holds
// the name that connect fails with errAdapterHeld, and any other failure leaves
// the session to create its own.
type adapterKeeper struct {
	gate    *adapterGate
	create  func() (keptAdapter, error)
	done    chan struct{} // closed when the first create has returned
	mu      sync.Mutex
	adapter keptAdapter // nil until created, after a failed create, and after a close
	closed  bool
}

// startAdapterKeeper claims the gate before it returns, so no start slips in
// ahead of the create, and creates the adapter in the background.
func startAdapterKeeper(gate *adapterGate, create func() (keptAdapter, error)) *adapterKeeper {
	release, err := gate.claim(desktopAdapterWait)
	if err != nil {
		log.Printf("[tun] kept adapter not created: %v", err)
		return nil
	}
	k := &adapterKeeper{gate: gate, create: create, done: make(chan struct{})}
	go func() {
		defer close(k.done)
		defer release()
		if err := k.createLocked(); err != nil {
			log.Printf("[tun] kept adapter not created: %v", err)
		}
	}()
	return k
}

// createLocked creates the adapter when none is held. The caller holds the
// gate.
func (k *adapterKeeper) createLocked() error {
	adapter, err := k.create()
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		_ = adapter.Close()
		return nil
	}
	k.adapter = adapter
	return nil
}

// ensure creates the adapter again when the keeper holds none or the one it
// holds was lost, and returns why it could not. The caller holds the gate, so
// no session is running.
func (k *adapterKeeper) ensure() error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	held, closed := k.adapter, k.closed
	k.mu.Unlock()
	if closed || (held != nil && held.Usable()) {
		return nil
	}
	if held != nil {
		_ = held.Close()
		k.mu.Lock()
		k.adapter = nil
		k.mu.Unlock()
	}
	return k.createLocked()
}

// close removes the adapter once the create has returned and no session holds
// the gate. A session still running after the wait loses its adapter, which is
// the process ending.
func (k *adapterKeeper) close() {
	if k == nil {
		return
	}
	k.mu.Lock()
	k.closed = true
	k.mu.Unlock()
	<-k.done
	release, err := k.gate.claim(desktopAdapterKeeperWait)
	if err == nil {
		defer release()
	}
	k.mu.Lock()
	adapter := k.adapter
	k.adapter = nil
	k.mu.Unlock()
	if adapter != nil {
		_ = adapter.Close()
	}
}

var (
	desktopKeeperOnce sync.Once
	desktopKeeper     atomic.Pointer[adapterKeeper]
)

// KeepDesktopAdapter creates the adapter the sessions of this process open,
// when the process may: the service, and an elevated process running the core
// itself. A client that forwards to the service keeps none.
func KeepDesktopAdapter() {
	desktopKeeperOnce.Do(func() { desktopKeeper.Store(startDesktopAdapterKeeper()) })
}

// CloseDesktopAdapter removes the kept adapter, on an orderly shutdown.
func CloseDesktopAdapter() {
	desktopKeeper.Load().close()
}

// claimDesktopAdapter takes desktopAdapterGate for a session of either engine,
// once the keeper's create or the last session's Close has returned. With the
// keeper's adapter missing it tries the create again first, so a core that lost
// the adapter to another process gets it back when that one leaves, and one
// that still finds the name held fails the start here, before either engine
// builds anything, with the reason in the status.
func claimDesktopAdapter() (release func(), err error) {
	release, err = desktopAdapterGate.claim(desktopAdapterWait)
	if err != nil {
		return nil, err
	}
	if err := desktopKeeper.Load().ensure(); errors.Is(err, errAdapterHeld) {
		release()
		return nil, err
	}
	return release, nil
}
