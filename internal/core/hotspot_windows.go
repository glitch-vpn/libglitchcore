//go:build windows

package core

import (
	"fmt"
	"math"
	"net/netip"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
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

// load finds the exports in System32; a Windows without them leaves the live
// switch unavailable.
func (c *icsClient) load() error {
	c.once.Do(func() {
		library := windows.NewLazySystemDLL("HNetCfgClient.dll")
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

// SharedPair reads ICS's pair from the sharing exports, and from the Mobile
// hotspot service's own record of it where they are missing. A side that is
// not shared reads as math.MaxUint32; an error is a pair that cannot be read.
func (o *windowsHotspotOS) SharedPair() (uint32, uint32, error) {
	if sharingExports.load() != nil {
		return sharedPairFromRegistry()
	}
	// A call that fails says that ICS has no such side.
	public, _ := sharingExports.index(sharingExports.getPublic, "HNetCfgGetPublicIndex")
	private, _ := sharingExports.index(sharingExports.getPrivate, "HNetCfgGetPrivateIndex")
	return public, private, nil
}

const sharedAccessIndexKeyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\SharedAccess`

func sharedPairFromRegistry() (public, private uint32, err error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, sharedAccessIndexKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return math.MaxUint32, math.MaxUint32, fmt.Errorf("read the hotspot service's pair: %w", err)
	}
	defer key.Close()
	read := func(name string) uint32 {
		value, _, err := key.GetIntegerValue(name)
		if err != nil || !validInterfaceIndex(uint32(value)) {
			return math.MaxUint32
		}
		return uint32(value)
	}
	return read("PublicIndex"), read("PrivateIndex"), nil
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

// TunnelIndex finds the tunnel's adapter by its GUID, which its name fixes.
func (o *windowsHotspotOS) TunnelIndex() (uint32, bool) {
	adapter, ok := findAdapter(func(adapter *winipcfg.IPAdapterAddresses) bool {
		return strings.EqualFold(adapter.AdapterName(), adapterGUID(desktopAdapterName).String())
	})
	if !ok {
		return 0, false
	}
	return adapter.IfIndex, true
}

func findAdapter(match func(*winipcfg.IPAdapterAddresses) bool) (*winipcfg.IPAdapterAddresses, bool) {
	adapters, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return nil, false
	}
	for _, adapter := range adapters {
		if adapter.IfIndex != 0 && match(adapter) {
			return adapter, true
		}
	}
	return nil, false
}

func (o *windowsHotspotOS) IsPhysical(index uint32) bool {
	if !validInterfaceIndex(index) {
		return false
	}
	tunnel := adapterGUID(desktopAdapterName).String()
	adapter, ok := findAdapter(func(adapter *winipcfg.IPAdapterAddresses) bool { return adapter.IfIndex == index })
	return ok && adapter.OperStatus == winipcfg.IfOperStatusUp && !strings.EqualFold(adapter.AdapterName(), tunnel)
}

// PhysicalIndex is the interface of the IPv4 default route with the lowest
// route-plus-interface metric, which is how Windows ranks them, among the
// interfaces that are physical.
func (o *windowsHotspotOS) PhysicalIndex() (uint32, bool) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return 0, false
	}
	bestMetric, best := uint32(math.MaxUint32), uint32(0)
	for i := range routes {
		route := &routes[i]
		if route.DestinationPrefix.PrefixLength != 0 || !o.IsPhysical(route.InterfaceIndex) {
			continue
		}
		metric := route.Metric
		if row, err := ipv4Interface(route.InterfaceIndex); err == nil {
			metric += row.Metric
		}
		if metric < bestMetric {
			bestMetric, best = metric, route.InterfaceIndex
		}
	}
	return best, best != 0
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
