//go:build windows && !no_awg

package core

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/ipc"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

func (x *CoreController) platformAwgStart(ifName string, _ int, settings string) (int, error) {
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()

	handle := x.nextHandle
	x.nextHandle++

	tunDev, err := tun.CreateTUN(ifName, defaultTunMTU)
	if err != nil {
		return -1, fmt.Errorf("create TUN: %w", err)
	}
	name := ifName
	x.awgIFName = ifName

	awgDev := device.NewDevice(
		tunDev,
		conn.NewDefaultBind(),
		device.NewLogger(awgDeviceLogLevel(), "[AWG] "),
	)
	awgDev.DisableSomeRoamingForBrokenMobileSemantics()

	if err = awgDev.IpcSet(settings); err != nil {
		tunDev.Close()
		return -1, fmt.Errorf("config AWG: %w", err)
	}

	var uapiL net.Listener
	if l, err := ipc.UAPIListen(name); err == nil {
		uapiL = l
		go func() {
			for {
				c, err := uapiL.Accept()
				if err != nil {
					return
				}
				go awgDev.IpcHandle(c)
			}
		}()
	}

	if err = awgDev.Up(); err != nil && !errors.Is(err, syscall.EPERM) {
		if uapiL != nil {
			uapiL.Close()
		}
		awgDev.Close()
		return -1, fmt.Errorf("start AWG: %w", err)
	}

	x.awgHandles[handle] = &awgHandle{
		ID:      handle,
		Device:  awgDev,
		Tunnel:  tunDev,
		UAPI:    uapiL,
		Config:  settings,
		Created: time.Now(),
		Running: true,
	}

	x.awgDevice = awgDev
	x.awgTunnel = tunDev

	x.emitStatus(EngineConnected, fmt.Sprintf("AWG tunnel %d started", handle))
	return handle, nil
}
