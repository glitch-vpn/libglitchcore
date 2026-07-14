//go:build !no_awg

package core

import (
	"net"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
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
	awgDevice  *device.Device
	awgTunnel  tun.Device
}

func (x *CoreController) initEngineState() {
	x.awgHandles = make(map[int]*awgHandle)
	x.currentAwgHandle = 0
	x.nextHandle = 1
}
