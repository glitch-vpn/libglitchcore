//go:build windows

package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A per-client block is a Windows Filtering Platform filter at the IPv4
// forward layer that blocks a client's address as the source, in a session
// whose filters go with it: when the process ends, so do they.

var (
	fwpuclnt               = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen     = fwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose    = fwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmSubLayerAdd    = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procFwpmFilterAdd      = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFwpmFilterDeleteBy = fwpuclnt.NewProc("FwpmFilterDeleteById0")
	layerIPForwardV4       = windows.GUID{Data1: 0xa82acc24, Data2: 0x4ee1, Data3: 0x4ee1, Data4: [8]byte{0xb4, 0x65, 0xfd, 0x1d, 0x25, 0xcb, 0x10, 0xa4}}
	conditionIPSourceAddr  = windows.GUID{Data1: 0xae96897e, Data2: 0x2e94, Data3: 0x4bc9, Data4: [8]byte{0xb3, 0x13, 0xb2, 0x7e, 0xe8, 0x0e, 0x57, 0x4d}}
)

// The layouts are those of fwpmtypes.h and fwptypes.h on a 64-bit Windows;
// the sizes are asserted in the tests.
const (
	fwpmSessionFlagDynamic = 0x1
	rpcAuthnWinNT          = 10
	fwpMatchEqual          = 0
	fwpV4AddrMask          = 0x100
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

type fwpmFilterCondition struct {
	FieldKey  windows.GUID
	MatchType uint32
	_         uint32
	ValueType uint32
	_         uint32
	Value     uint64
}

type fwpV4AddrAndMask struct {
	Address uint32
	Mask    uint32
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
	filters  map[netip.Addr]uint64
}

func fwpmError(call string, result uintptr) error {
	if result == 0 {
		return nil
	}
	return fmt.Errorf("%s: 0x%08X", call, uint32(result))
}

// set makes the blocked addresses exactly these; none closes the session.
func (b *clientBlocker) set(addresses []netip.Addr) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(addresses) == 0 {
		b.close()
		return nil
	}
	if unsafe.Sizeof(uintptr(0)) != 8 {
		return errors.New("the client block needs a 64-bit Windows")
	}
	if err := b.open(); err != nil {
		return err
	}
	var problems []error
	for address, id := range b.filters {
		if !slices.Contains(addresses, address) {
			result, _, _ := procFwpmFilterDeleteBy.Call(uintptr(b.engine), uintptr(id))
			if err := fwpmError("FwpmFilterDeleteById0", result); err != nil {
				problems = append(problems, err)
				continue
			}
			delete(b.filters, address)
		}
	}
	for _, address := range addresses {
		if _, held := b.filters[address]; held {
			continue
		}
		id, err := b.add(address)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", address, err))
			continue
		}
		b.filters[address] = id
	}
	return errors.Join(problems...)
}

func (b *clientBlocker) open() error {
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
	b.engine, b.subLayer, b.filters = engine, key, map[netip.Addr]uint64{}
	return nil
}

// close ends the session, which removes every filter it holds.
func (b *clientBlocker) close() {
	if b.engine == 0 {
		return
	}
	procFwpmEngineClose.Call(uintptr(b.engine))
	b.engine, b.filters = 0, nil
}

func (b *clientBlocker) add(address netip.Addr) (uint64, error) {
	octets := address.As4()
	match := &fwpV4AddrAndMask{Address: binary.BigEndian.Uint32(octets[:]), Mask: 0xFFFFFFFF}
	condition := &fwpmFilterCondition{
		FieldKey:  conditionIPSourceAddr,
		MatchType: fwpMatchEqual,
		ValueType: fwpV4AddrMask,
		Value:     uint64(uintptr(unsafe.Pointer(match))),
	}
	key, err := windows.GenerateGUID()
	if err != nil {
		return 0, err
	}
	name, _ := windows.UTF16PtrFromString("Glitch hotspot client block " + address.String())
	filter := &fwpmFilter{
		FilterKey:           key,
		DisplayData:         fwpmDisplayData{Name: name},
		LayerKey:            layerIPForwardV4,
		SubLayerKey:         b.subLayer,
		NumFilterConditions: 1,
		FilterCondition:     condition,
		ActionType:          fwpActionBlock,
	}
	var id uint64
	result, _, _ := procFwpmFilterAdd.Call(uintptr(b.engine), uintptr(unsafe.Pointer(filter)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(match)
	runtime.KeepAlive(condition)
	if err := fwpmError("FwpmFilterAdd0", result); err != nil {
		return 0, err
	}
	return id, nil
}
