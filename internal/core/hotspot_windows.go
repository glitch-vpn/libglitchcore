//go:build windows

package core

import (
	"fmt"
	"math"
	"net/netip"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const hotspotSupported = true

// icsClient is HNetCfgClient.dll's sharing calls, which the Mobile hotspot
// service itself makes. Windows documents none of them; they are read off
// Windows 11 23H2's disassembly (public index first, private second).
type icsClient struct {
	once sync.Once
	err  error

	getPublic, getPrivate, start, stop *windows.LazyProc
}

var sharingExports icsClient

// load finds the exports in System32 by their full path; a Windows without them
// leaves the live switch unavailable.
func (c *icsClient) load() error {
	c.once.Do(func() {
		directory, err := windows.GetSystemDirectory()
		if err != nil {
			c.err = fmt.Errorf("find System32: %w", err)
			return
		}
		library := windows.NewLazyDLL(filepath.Join(directory, "HNetCfgClient.dll"))
		c.getPublic = library.NewProc("HNetCfgGetPublicIndex")
		c.getPrivate = library.NewProc("HNetCfgGetPrivateIndex")
		c.start = library.NewProc("HNetCfgStartSharing")
		c.stop = library.NewProc("HNetCfgStopSharing")
		for _, proc := range []*windows.LazyProc{c.getPublic, c.getPrivate, c.start, c.stop} {
			if err := proc.Find(); err != nil {
				c.err = err
				return
			}
		}
	})
	return c.err
}

func hresultError(call string, result uintptr) error {
	if int32(result) == 0 {
		return nil
	}
	return fmt.Errorf("%s: 0x%08X", call, uint32(result))
}

func (c *icsClient) index(proc *windows.LazyProc, name string) (uint32, error) {
	if err := c.load(); err != nil {
		return math.MaxUint32, err
	}
	var index uint32
	result, _, _ := proc.Call(uintptr(unsafe.Pointer(&index)))
	if err := hresultError(name, result); err != nil {
		return math.MaxUint32, err
	}
	return index, nil
}

type windowsHotspotOS struct {
	wfp clientBlocker
}

func newHotspotOS() hotspotOS { return &windowsHotspotOS{} }

func (o *windowsHotspotOS) SharingAvailable() bool { return sharingExports.load() == nil }

func (o *windowsHotspotOS) SharedPair() (uint32, uint32, error) {
	if err := sharingExports.load(); err != nil {
		return math.MaxUint32, math.MaxUint32, err
	}
	// A call that fails says that ICS has no such side: both come back as
	// math.MaxUint32 then.
	public, _ := sharingExports.index(sharingExports.getPublic, "HNetCfgGetPublicIndex")
	private, _ := sharingExports.index(sharingExports.getPrivate, "HNetCfgGetPrivateIndex")
	return public, private, nil
}

func (o *windowsHotspotOS) Share(public, private uint32) error {
	if err := sharingExports.load(); err != nil {
		return err
	}
	result, _, _ := sharingExports.start.Call(uintptr(public), uintptr(private))
	return hresultError("HNetCfgStartSharing", result)
}

func (o *windowsHotspotOS) Unshare(public, private uint32) error {
	if err := sharingExports.load(); err != nil {
		return err
	}
	result, _, _ := sharingExports.stop.Call(uintptr(public), uintptr(private))
	return hresultError("HNetCfgStopSharing", result)
}

func (o *windowsHotspotOS) TunnelIndex() (uint32, bool) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return 0, false
	}
	for _, adapter := range adapters {
		if adapter.FriendlyName() == desktopAdapterName && adapter.IfIndex != 0 {
			return adapter.IfIndex, true
		}
	}
	return 0, false
}

// PhysicalIndex is the interface of the IPv4 default route with the lowest
// metric that is not the tunnel's.
func (o *windowsHotspotOS) PhysicalIndex() (uint32, bool) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return 0, false
	}
	tunnel, _ := o.TunnelIndex()
	var best *winipcfg.MibIPforwardRow2
	for i := range routes {
		route := &routes[i]
		if route.DestinationPrefix.PrefixLength != 0 || route.InterfaceIndex == tunnel {
			continue
		}
		if best == nil || route.Metric < best.Metric {
			best = route
		}
	}
	if best == nil {
		return 0, false
	}
	return best.InterfaceIndex, true
}

func ipv4Interface(index uint32) (*winipcfg.MibIPInterfaceRow, error) {
	luid, err := winipcfg.LUIDFromIndex(index)
	if err != nil {
		return nil, err
	}
	return luid.IPInterface(windows.AF_INET)
}

func (o *windowsHotspotOS) Forwarding(index uint32) (bool, error) {
	row, err := ipv4Interface(index)
	if err != nil {
		return false, err
	}
	return row.ForwardingEnabled, nil
}

func (o *windowsHotspotOS) SetForwarding(index uint32, on bool) error {
	row, err := ipv4Interface(index)
	if err != nil {
		return err
	}
	row.ForwardingEnabled = on
	return row.Set()
}

func (o *windowsHotspotOS) BlockClients(addresses []netip.Addr) error {
	return o.wfp.set(addresses)
}
