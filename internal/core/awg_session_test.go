//go:build !no_awg

package core

import (
	"bytes"
	"encoding/base64"
	"errors"
	"sync"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// awgDevices stands in for the system TUN: it records the descriptor each
// device was brought up on and which went down.
type awgDevices struct {
	mu   sync.Mutex
	fds  map[int]int
	down map[int]bool
}

func standInAwgDevices(t *testing.T) *awgDevices {
	t.Helper()
	d := &awgDevices{fds: map[int]int{}, down: map[int]bool{}}
	prevUp, prevDown := awgDeviceUp, awgDeviceDown
	awgDeviceUp = func(x *CoreController, _ string, tunFd *tunCopy, _, _, _ string) (int, error) {
		dev := device.NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
		handle := x.nextHandle
		x.nextHandle++
		x.awgHandles[handle] = &awgHandle{ID: handle, Device: dev, Running: true}
		x.awgDevice.Store(dev)
		d.mu.Lock()
		d.fds[handle] = tunFd.take()
		d.mu.Unlock()
		return handle, nil
	}
	awgDeviceDown = func(x *CoreController, handle int) error {
		d.mu.Lock()
		d.down[handle] = true
		d.mu.Unlock()
		return x.awgStopHandleLocked(handle)
	}
	t.Cleanup(func() { awgDeviceUp, awgDeviceDown = prevUp, prevDown })
	return d
}

// Made-up keys the UAPI parser accepts; nothing dials the endpoint.
var awgSessionTestConfig = `[Interface]
PrivateKey = ` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + `
Address = 10.8.0.2/32

[Peer]
PublicKey = ` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)) + `
Endpoint = 192.0.2.7:51820
AllowedIPs = 0.0.0.0/0
`

func awgStartOn(tunFd int) EngineStartRequest {
	return EngineStartRequest{Config: awgSessionTestConfig, TunFD: tunFd, Opts: map[string]string{"resolveExternalIp": "0", "livenessSec": "300"}}
}

func newAwgSessionController(t *testing.T) *CoreController {
	t.Helper()
	x := &CoreController{}
	x.initEngineState()
	t.Cleanup(func() {
		x.stopStats()
		x.coreMutex.Lock()
		defer x.coreMutex.Unlock()
		x.endSessionLoops()
		x.awgStopLocked()
	})
	return x
}

func TestAwgStop_TakenWhileALaterStartWaits(t *testing.T) {
	standInTunCopies(t)
	standInAwgDevices(t)
	x := newAwgSessionController(t)
	queuedStopScenario(t, x, "awg", &x.awgSession, x.HandleAwgStart, x.HandleAwgStop, awgStartOn(101))
}

func TestAwgStart_ReplacesTheInstanceOfAStoppedSession(t *testing.T) {
	standInTunCopies(t)
	devices := standInAwgDevices(t)
	x := newAwgSessionController(t)

	replaceScenario(t, "awg", &x.awgSession, x.HandleAwgStart, x.HandleAwgStop, awgStartOn(101), awgStartOn(102))

	x.coreMutex.Lock()
	handle := x.currentAwgHandle
	_, aLeft := x.awgHandles[1]
	x.coreMutex.Unlock()
	devices.mu.Lock()
	defer devices.mu.Unlock()
	if devices.fds[handle] != 1102 {
		t.Fatalf("the running device came up on fd %d, want the copy of B's 102", devices.fds[handle])
	}
	if aLeft || !devices.down[1] {
		t.Fatal("A's device is still up")
	}
}

// The link pick runs before the start takes the lock and can take seconds;
// a stop in it is taken, and the start then gives up.
func TestAwgStop_TakenDuringTheLinkPick(t *testing.T) {
	standInTunCopies(t)
	standInAwgDevices(t)
	logs := captureLogs(t, 1)
	release := holdStarts(t, "awg")
	x := newAwgSessionController(t)

	if res := x.HandleAwgStart(awgStartOn(101)); res != glitchCoreResultSuccess {
		t.Fatalf("start = %d", res)
	}
	if res := x.HandleAwgStop(); res != glitchCoreResultSuccess {
		t.Fatalf("stop during the pick = %d, want it taken", res)
	}
	release(0)
	waitStartsGivenUp(t, logs, 1)
	waitStartsInFlight(t, &x.awgSession, 0)
	if x.awgSession.running.Load() {
		t.Fatal("awg runs after a stop during its link pick")
	}
}

func TestAwgStop_LeavesTheInstanceOfALaterStart(t *testing.T) {
	x := &CoreController{}
	x.awgSession.up(2)

	if err := x.awgStop(2); !errors.Is(err, errStopSuperseded) {
		t.Fatalf("stop of generation 2 over an instance started under 2: %v", err)
	}
	if !x.awgSession.running.Load() {
		t.Fatal("the stop marked the later session's engine stopped")
	}
}
