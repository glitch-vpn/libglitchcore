//go:build windows && !with_tun2socks

// Package wintun stands in for golang.zx2c4.com/wintun in the main variant.
// xray-core's TUN, WireGuard and masque packages link the binding, and no
// config the core builds uses it: sing-tun loads the wintun.dll beside the
// core, and a second binding in the same process would be a second way to
// load it. Every call refuses. The tun2socks variant builds the upstream
// binding, copied beside this file.
package wintun

import (
	"errors"

	"golang.org/x/sys/windows"
)

// ErrNotSupported is what every call returns.
var ErrNotSupported = errors.New("this build drives Wintun through sing-tun only")

const (
	AdapterNameMax  = 128
	PacketSizeMax   = 0xffff
	RingCapacityMin = 0x20000
	RingCapacityMax = 0x4000000
)

type Adapter struct{}

type Session struct{}

func CreateAdapter(name string, tunnelType string, requestedGUID *windows.GUID) (*Adapter, error) {
	return nil, ErrNotSupported
}

func OpenAdapter(name string) (*Adapter, error) { return nil, ErrNotSupported }

func Uninstall() error { return ErrNotSupported }

func RunningVersion() (uint32, error) { return 0, ErrNotSupported }

func Version() string { return "unknown" }

func (wintun *Adapter) Close() error { return ErrNotSupported }

func (wintun *Adapter) LUID() uint64 { return 0 }

func (wintun *Adapter) StartSession(capacity uint32) (Session, error) {
	return Session{}, ErrNotSupported
}

func (session Session) End() {}

func (session Session) ReadWaitEvent() windows.Handle { return 0 }

func (session Session) ReceivePacket() ([]byte, error) { return nil, ErrNotSupported }

func (session Session) ReleaseReceivePacket(packet []byte) {}

func (session Session) AllocateSendPacket(packetSize int) ([]byte, error) {
	return nil, ErrNotSupported
}

func (session Session) SendPacket(packet []byte) {}
