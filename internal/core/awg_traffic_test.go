//go:build !no_awg

package core

import (
	"sync"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

func newIdleAwgDevice(t *testing.T) *device.Device {
	t.Helper()
	dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	return dev
}

func TestAwgTraffic_ReadsWhileAStartOrStopHoldsTheCore(t *testing.T) {
	x := &CoreController{}
	x.initEngineState()
	x.awgDevice.Store(newIdleAwgDevice(t))
	x.isAwgRunning.Store(true)

	if _, _, running := readTrafficWhileTheCoreIsHeld(t, x); !running {
		t.Fatal("a running awg session read as not running")
	}
}

// Run with -race: a stop closes the device the readers dump.
func TestAwgTraffic_ReadsRaceAStop(t *testing.T) {
	x := &CoreController{}
	x.initEngineState()
	var readers sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					x.readEngineTraffic()
					_, _ = x.awgDeviceState()
				}
			}
		}()
	}
	for handle := 1; handle <= 50; handle++ {
		dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
		x.coreMutex.Lock()
		x.awgHandles[handle] = &awgHandle{ID: handle, Device: dev, Running: true}
		x.coreMutex.Unlock()
		x.awgDevice.Store(dev)
		x.isAwgRunning.Store(true)
		if err := x.awgStopHandle(handle); err != nil {
			t.Fatal(err)
		}
		x.isAwgRunning.Store(false)
	}
	close(stop)
	readers.Wait()
	if x.awgDevice.Load() != nil {
		t.Fatal("a stopped session left its device readable")
	}
}
