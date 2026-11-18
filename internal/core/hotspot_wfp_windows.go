//go:build windows

package core

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A per-client block is a Windows Filtering Platform filter at the inbound
// Ethernet frame layer that drops every frame a client's MAC address sends in
// on the hotspot's adapter, in a session whose filters go with it: when the
// process ends, so do they. The client reaches nothing beyond the PC, and
// Android drops its connection to the network. The same device on another
// adapter of the PC is not touched.
//
// The IP layers cannot say it. At the IPv4 forward layer a condition on the
// client as the source never matches, ICS having translated its packets by
// then, and one on the client as the destination drops only the replies, not
// what the client sends needing none.

var (
	fwpuclnt                     = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen           = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose          = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd          = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd            = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteBy       = fwpuclnt.NewProc("FwpmFilterDeleteById0")
	layerInboundMACFrameEthernet = windows.GUID{Data1: 0xeffb7edb, Data2: 0x0055, Data3: 0x4f9a, Data4: [8]byte{0xa2, 0x31, 0x4f, 0xf8, 0x13, 0x1a, 0xd1, 0x91}}
	conditionInterfaceIndex      = windows.GUID{Data1: 0x667fd755, Data2: 0xd695, Data3: 0x434a, Data4: [8]byte{0x8a, 0xf5, 0xd3, 0x83, 0x5a, 0x12, 0x59, 0xbc}}
	conditionMACRemoteAddress    = windows.GUID{Data1: 0x408f2ed4, Data2: 0x3a70, Data3: 0x4b4d, Data4: [8]byte{0x92, 0xa6, 0x41, 0x5a, 0xc2, 0x0e, 0x2f, 0x12}}
)

// The layouts are those of fwpmtypes.h and fwptypes.h on a 64-bit Windows;
// the sizes are asserted in the tests.
const (
	fwpmSessionFlagDynamic = 0x1
	rpcAuthnWinNT          = 10
	fwpMatchEqual          = 0
	fwpUint32Type          = 3
	fwpByteArray6Type      = 18
	fwpActionBlock         = 0x1001
	wfpBlockSubLayerWeight = 0xFFFF
)

type fwpmDisplayData struct {
	Name        *uint16
	Description *uint16
}

type fwpmSession struct {
	SessionKey           windows.GUID
	DisplayData          fwpmDisplayData
	Flags                uint32
	TxnWaitTimeoutMillis uint32
	ProcessID            uint32
	_                    uint32
	SID                  uintptr
	Username             *uint16
	KernelMode           int32
	_                    uint32
}

type fwpmSubLayer struct {
	SubLayerKey      windows.GUID
	DisplayData      fwpmDisplayData
	Flags            uint32
	_                uint32
	ProviderKey      *windows.GUID
	ProviderDataSize uint32
	_                uint32
	ProviderData     uintptr
	Weight           uint16
	_                [6]byte
}

// fwpmFilterCondition is a condition whose value the union holds by reference;
// the pointer keeps what it points at alive and in place.
type fwpmFilterCondition struct {
	FieldKey  windows.GUID
	MatchType uint32
	_         uint32
	ValueType uint32
	_         uint32
	Value     unsafe.Pointer
}

// fwpmFilterConditionUint32 is the same layout with a value the union holds
// inline.
type fwpmFilterConditionUint32 struct {
	FieldKey  windows.GUID
	MatchType uint32
	_         uint32
	ValueType uint32
	_         uint32
	Value     uint32
	_         uint32
}

// macFrameConditions is the two conditions of a block, one after the other as
// the filter reads them.
type macFrameConditions struct {
	mac       fwpmFilterCondition
	hotspotIf fwpmFilterConditionUint32
}

type fwpmFilter struct {
	FilterKey           windows.GUID
	DisplayData         fwpmDisplayData
	Flags               uint32
	_                   uint32
	ProviderKey         *windows.GUID
	ProviderDataSize    uint32
	_                   uint32
	ProviderData        uintptr
	LayerKey            windows.GUID
	SubLayerKey         windows.GUID
	WeightType          uint32
	_                   uint32
	WeightValue         uint64
	NumFilterConditions uint32
	_                   uint32
	FilterCondition     *fwpmFilterCondition
	ActionType          uint32
	ActionFilterType    windows.GUID
	_                   uint32
	RawContext          uint64
	_                   uint64
	Reserved            uintptr
	FilterID            uint64
	EffectiveWeightType uint32
	_                   uint32
	EffectiveWeight     uint64
}

type clientBlocker struct {
	mu       sync.Mutex
	engine   windows.Handle
	subLayer windows.GUID
	filters  map[string]uint64
	hotspot  uint32 // the interface the filters are held on
}

func fwpmError(call string, result uintptr) error {
	if result == 0 {
		return nil
	}
	return fmt.Errorf("%s: 0x%08X", call, uint32(result))
}

// set makes the blocked devices exactly these, on the hotspot's interface; no
// devices, or no interface, closes the session. A filter holds an interface
// index, so a changed one closes the session and holds the devices again.
func (b *clientBlocker) set(hotspot uint32, macs []net.HardwareAddr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(macs) == 0 || hotspot == 0 {
		b.close()
		return nil
	}
	if b.engine != 0 && b.hotspot != hotspot {
		b.close()
	}
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return errors.New("the client block needs a 64-bit Windows")
	}
	if err := b.open(hotspot); err != nil {
		return err
	}
	var problems []error
	wanted := make(map[string]net.HardwareAddr, len(macs))
	for _, mac := range macs {
		wanted[mac.String()] = mac
	}
	for key, id := range b.filters {
		if _, keep := wanted[key]; !keep {
			result, _, _ := procFwpmFilterDeleteBy.Call(uintptr(b.engine), uintptr(id))
			if err := fwpmError("FwpmFilterDeleteById0", result); err != nil {
				problems = append(problems, err)
				continue
			}
			delete(b.filters, key)
		}
	}
	for key, mac := range wanted {
		if _, held := b.filters[key]; held {
			continue
		}
		id, err := b.add(hotspot, mac)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", key, err))
			continue
		}
		b.filters[key] = id
	}
	return errors.Join(problems...)
}

func (b *clientBlocker) open(hotspot uint32) error {
	if b.engine != 0 {
		return nil
	}
	name, _ := windows.UTF16PtrFromString("Glitch hotspot client block")
	session := &fwpmSession{Flags: fwpmSessionFlagDynamic, DisplayData: fwpmDisplayData{Name: name}}
	var engine windows.Handle
	result, _, _ := procFwpmEngineOpen.Call(0, rpcAuthnWinNT, 0, uintptr(unsafe.Pointer(session)), uintptr(unsafe.Pointer(&engine)))
	if err := fwpmError("FwpmEngineOpen0", result); err != nil {
		return err
	}
	key, err := windows.GenerateGUID()
	if err != nil {
		procFwpmEngineClose.Call(uintptr(engine))
		return err
	}
	subLayer := &fwpmSubLayer{SubLayerKey: key, DisplayData: fwpmDisplayData{Name: name}, Weight: wfpBlockSubLayerWeight}
	result, _, _ = procFwpmSubLayerAdd.Call(uintptr(engine), uintptr(unsafe.Pointer(subLayer)), 0)
	if err := fwpmError("FwpmSubLayerAdd0", result); err != nil {
		procFwpmEngineClose.Call(uintptr(engine))
		return err
	}
	b.engine, b.subLayer, b.filters = engine, key, map[string]uint64{}
	b.hotspot = hotspot
	return nil
}

// close ends the session, which removes every filter it holds.
func (b *clientBlocker) close() {
	if b.engine == 0 {
		return
	}
	procFwpmEngineClose.Call(uintptr(b.engine))
	b.engine, b.filters, b.hotspot = 0, nil, 0
}

func (b *clientBlocker) add(hotspot uint32, mac net.HardwareAddr) (uint64, error) {
	if len(mac) != 6 {
		return 0, fmt.Errorf("%q is not a 6-byte MAC address", mac.String())
	}
	match := new([6]byte)
	copy(match[:], mac)
	conditions := &macFrameConditions{
		mac: fwpmFilterCondition{
			FieldKey:  conditionMACRemoteAddress,
			MatchType: fwpMatchEqual,
			ValueType: fwpByteArray6Type,
			Value:     unsafe.Pointer(match),
		},
		hotspotIf: fwpmFilterConditionUint32{
			FieldKey:  conditionInterfaceIndex,
			MatchType: fwpMatchEqual,
			ValueType: fwpUint32Type,
			Value:     hotspot,
		},
	}
	key, err := windows.GenerateGUID()
	if err != nil {
		return 0, err
	}
	name, _ := windows.UTF16PtrFromString(fmt.Sprintf("Glitch hotspot client block %s on %d", mac, hotspot))
	filter := &fwpmFilter{
		FilterKey:           key,
		DisplayData:         fwpmDisplayData{Name: name},
		LayerKey:            layerInboundMACFrameEthernet,
		SubLayerKey:         b.subLayer,
		NumFilterConditions: 2,
		FilterCondition:     &conditions.mac,
		ActionType:          fwpActionBlock,
	}
	var id uint64
	result, _, _ := procFwpmFilterAdd.Call(uintptr(b.engine), uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(conditions)
	if err := fwpmError("FwpmFilterAdd0", result); err != nil {
		return 0, err
	}
	return id, nil
}
