//go:build android && !no_awg

package core

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// The caller holds coreMutex.
func (x *CoreController) platformAwgStart(ifName string, tunFd *tunCopy, settings string) (int, error) {
	handle := x.nextHandle
	x.nextHandle++

	dupFd := tunFd.take()
	if dupFd < 0 {
		return -1, errors.New("no TUN fd")
	}

	// The dup stays ours until CreateUnmonitoredTUNFromFD wraps it in an
	// os.File; from then on the file owns it and a close here would hit a
	// number the file's finalizer closes again.
	unclaimedTunFd := dupFd
	defer func() {
		if unclaimedTunFd >= 0 {
			closeTunFd(unclaimedTunFd)
		}
	}()
	if err := syscall.SetNonblock(dupFd, true); err != nil {
		return -1, fmt.Errorf("create TUN: %w", err)
	}
	unclaimedTunFd = -1

	tunDev, name, err := tun.CreateUnmonitoredTUNFromFD(dupFd)
	if err != nil {
		return -1, fmt.Errorf("create TUN: %w", err)
	}

	x.awgIFName = name

	awgDev := device.NewDevice(
		tunDev,
		conn.NewStdNetBind(),
		awgDeviceLogger(),
	)
	awgDev.DisableSomeRoamingForBrokenMobileSemantics()

	if err = awgDev.IpcSet(settings); err != nil {
		tunDev.Close()
		return -1, fmt.Errorf("config AWG: %w", err)
	}

	var uapiL net.Listener
	if uapiFile, err := ipc.UAPIOpen(name); err == nil {
		if l, err := ipc.UAPIListen(name, uapiFile); err == nil {
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
		} else {
			uapiFile.Close()
		}
	}

	// The kernel returns EPERM on netlink up without CAP_NET_ADMIN; treat
	// everything else as fatal.
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

	x.awgDevice.Store(awgDev)
	x.awgTunnel = tunDev

	return handle, nil
}
