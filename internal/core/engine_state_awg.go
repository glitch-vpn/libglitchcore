//go:build !no_awg

package core

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

type awgHandle struct {
	ID      int
	Device  *device.Device
	Tunnel  tun.Device
	UAPI    net.Listener
	Config  string
	Created time.Time
	Running bool
}

type awgState struct {
	awgHandles map[int]*awgHandle
	// The running device, read without coreMutex: a start or a stop holds it
	// for its whole run, and the device guards its own state.
	awgDevice atomic.Pointer[device.Device]
	awgTunnel tun.Device
}

func (x *CoreController) initEngineState() {
	x.awgHandles = make(map[int]*awgHandle)
	x.currentAwgHandle = 0
	x.nextHandle = 1
}
