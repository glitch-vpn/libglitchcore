//go:build !no_xray && !with_tun2socks && with_gvisor

package core

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	tun "github.com/metacubex/sing-tun"
)

// countedTun is a session's device: closing it ends the session and nothing
// else.
type countedTun struct {
	channelTun
	closed *atomic.Int32
}

func (d countedTun) Close() error {
	d.closed.Add(1)
	return nil
}

// Every connect opens a device on the one adapter and every stop closes that
// device only: the adapter is created once for the process and is not closed
// by a stop.
func TestXrayTunLayer_SessionsShareTheKeptAdapter(t *testing.T) {
	prevNew := newTunDevice
	t.Cleanup(func() { newTunDevice = prevNew })

	var adapterCreates atomic.Int32
	adapter := &fakeKeptAdapter{}
	finish := make(chan struct{})
	var finishOnce sync.Once
	finishCreate := func() { finishOnce.Do(func() { close(finish) }) }
	k := startAdapterKeeper(&desktopAdapterGate, func() (keptAdapter, error) {
		adapterCreates.Add(1)
		<-finish
		return adapter, nil
	})
	desktopKeeper.Store(k)
	opened := make(chan func())
	stop := make(chan struct{})
	var connect sync.WaitGroup
	// Every exit path lets the create return, gives back the gate a connect
	// still holds and releases the keeper's, so a failure here cannot hold the
	// gate for the tests after.
	t.Cleanup(func() {
		finishCreate()
		close(stop)
		connect.Wait()
		desktopKeeper.Store(nil)
		k.close()
	})

	var devices, deviceCloses atomic.Int32
	newTunDevice = func(tun.Options) (tun.Tun, error) {
		devices.Add(1)
		return countedTun{channelTun: channelTun{ep: channel.New(8, 1500, "")}, closed: &deviceCloses}, nil
	}

	connect.Add(1)
	go func() {
		defer connect.Done()
		_, release, err := openXrayTun(tunTestOptions(1500))
		if err != nil {
			t.Errorf("open: %v", err)
			return
		}
		select {
		case opened <- release:
		case <-stop:
			release()
		}
	}()
	select {
	case <-opened:
		t.Fatal("the first connect opened a device before the adapter was created")
	case <-time.After(150 * time.Millisecond):
	}
	finishCreate()
	release := <-opened
	if devices.Load() != 1 {
		t.Fatalf("%d devices after the first connect, want 1", devices.Load())
	}
	release()

	for i := 0; i < 2; i++ {
		device, release, err := openXrayTun(tunTestOptions(1500))
		if err != nil {
			t.Fatal(err)
		}
		_ = device.Close()
		release()
	}
	if devices.Load() != 3 || deviceCloses.Load() != 2 {
		t.Fatalf("devices opened %d, closed %d; want 3 and 2", devices.Load(), deviceCloses.Load())
	}
	if adapterCreates.Load() != 1 || adapter.closed.Load() != 0 {
		t.Fatalf("adapter created %d times, closed %d; want 1 and 0 across the sessions", adapterCreates.Load(), adapter.closed.Load())
	}
	desktopKeeper.Store(nil)
	k.close()
	if adapter.closed.Load() != 1 {
		t.Fatalf("adapter closed %d times at shutdown, want 1", adapter.closed.Load())
	}
}

// A name another process holds fails the connect with that reason, before a
// device is opened, and leaves the gate free.
func TestXrayTunLayer_AHeldAdapterNameFailsTheConnectWithTheReason(t *testing.T) {
	prevNew := newTunDevice
	t.Cleanup(func() { newTunDevice = prevNew })
	var devices atomic.Int32
	newTunDevice = func(tun.Options) (tun.Tun, error) {
		devices.Add(1)
		return countedTun{channelTun: channelTun{ep: channel.New(8, 1500, "")}, closed: new(atomic.Int32)}, nil
	}
	k := startAdapterKeeper(&desktopAdapterGate, func() (keptAdapter, error) { return nil, errAdapterHeld })
	<-k.done
	desktopKeeper.Store(k)
	t.Cleanup(func() { desktopKeeper.Store(nil); k.close() })

	_, _, err := openXrayTun(tunTestOptions(1500))
	if !errors.Is(err, errAdapterHeld) {
		t.Fatalf("err = %v; want the held reason", err)
	}
	if devices.Load() != 0 {
		t.Fatalf("%d devices opened on a held adapter", devices.Load())
	}
	release, err := desktopAdapterGate.claim(time.Second)
	if err != nil {
		t.Fatalf("the gate stayed held after the refusal: %v", err)
	}
	release()
}
