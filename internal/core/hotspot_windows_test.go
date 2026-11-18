//go:build windows

package core

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"unsafe"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func TestWFPKeysMatchTheHeaders(t *testing.T) {
	for name, got := range map[string][2]string{
		"FWPM_LAYER_IPFORWARD_V4":               {layerIPForwardV4.String(), "{A82ACC24-4EE1-4EE1-B465-FD1D25CB10A4}"},
		"FWPM_CONDITION_IP_DESTINATION_ADDRESS": {conditionIPDestinationAddr.String(), "{2D79133B-B390-45C6-8699-ACACEAAFED33}"},
	} {
		if got[0] != got[1] {
			t.Errorf("%s = %s, fwpmu.h says %s", name, got[0], got[1])
		}
	}
}

func TestWFPStructSizesMatchTheHeaders(t *testing.T) {
	for name, got := range map[string][2]uintptr{
		"FWPM_SESSION0":          {unsafe.Sizeof(fwpmSession{}), 72},
		"FWPM_SUBLAYER0":         {unsafe.Sizeof(fwpmSubLayer{}), 72},
		"FWPM_FILTER_CONDITION0": {unsafe.Sizeof(fwpmFilterCondition{}), 40},
		"FWPM_FILTER0":           {unsafe.Sizeof(fwpmFilter{}), 200},
		"FWP_V4_ADDR_AND_MASK":   {unsafe.Sizeof(fwpV4AddrAndMask{}), 8},
	} {
		if got[0] != got[1] {
			t.Errorf("%s is %d bytes, want %d", name, got[0], got[1])
		}
	}
	var filter fwpmFilter
	for name, got := range map[string][2]uintptr{
		"layerKey":        {unsafe.Offsetof(filter.LayerKey), 64},
		"subLayerKey":     {unsafe.Offsetof(filter.SubLayerKey), 80},
		"weightValue":     {unsafe.Offsetof(filter.WeightValue), 104},
		"filterCondition": {unsafe.Offsetof(filter.FilterCondition), 120},
		"actionType":      {unsafe.Offsetof(filter.ActionType), 128},
		"rawContext":      {unsafe.Offsetof(filter.RawContext), 152},
		"reserved":        {unsafe.Offsetof(filter.Reserved), 168},
		"filterId":        {unsafe.Offsetof(filter.FilterID), 176},
	} {
		if got[0] != got[1] {
			t.Errorf("fwpmFilter.%s is at %d, want %d", name, got[0], got[1])
		}
	}
}

func TestClientBlockerWithoutAddressesOpensNothing(t *testing.T) {
	var blocker clientBlocker
	if err := blocker.set(nil); err != nil {
		t.Fatal(err)
	}
	if err := blocker.set([]netip.Addr{}); err != nil {
		t.Fatal(err)
	}
	if blocker.engine != 0 {
		t.Error("an engine session was opened for no addresses")
	}
}

func TestICSSnapshotIsStaleOnlyForANameOfAGoneAdapter(t *testing.T) {
	present := map[string]bool{"{A}": true, "{B}": true}
	for name, tc := range map[string]struct {
		snapshot icsSnapshot
		stale    bool
	}{
		"clean":                    {icsSnapshot{present: present}, false},
		"flag of a present one":    {icsSnapshot{present: present, flags: []homeNetFlag{{guid: "{A}", public: true}}}, false},
		"flag of a gone one":       {icsSnapshot{present: present, flags: []homeNetFlag{{guid: "{A}", public: true}, {guid: "{X}", private: true}}}, true},
		"preferred present":        {icsSnapshot{present: present, preferredPublic: "{B}"}, false},
		"preferred gone":           {icsSnapshot{present: present, preferredPublic: "{X}"}, true},
		"neither flag nor setting": {icsSnapshot{present: map[string]bool{}}, false},
	} {
		if got := tc.snapshot.stale(); got != tc.stale {
			t.Errorf("%s: stale = %t, want %t", name, got, tc.stale)
		}
	}
}

func TestNormalizedGUIDReadsAWMIReference(t *testing.T) {
	reference := `\PC\root\Microsoft\HomeNet:HNet_Connection.Guid="{0a1b2c3d-0000-4000-8000-0123456789ab}"`
	if got, want := normalizedGUID(reference), "{0A1B2C3D-0000-4000-8000-0123456789AB}"; got != want {
		t.Errorf("normalizedGUID = %q, want %q", got, want)
	}
}

// The reads need no elevation and change nothing.
func TestWindowsHotspotOSReadsWithoutElevation(t *testing.T) {
	os := &windowsHotspotOS{}
	if !os.SharingAvailable() {
		t.Skip("HNetCfgClient.dll's sharing exports are absent on this Windows")
	}
	if _, _, err := os.SharedPair(); err != nil {
		t.Fatal(err)
	}
}

// The tunnel's adapter is found by a GUID its name fixes: the same two the sing-tun
// fork's own generator gives these names.
func TestAdapterGUIDIsFixedByTheName(t *testing.T) {
	for name, want := range map[string]string{
		"GlitchVPNMeta": "{6098DEC3-A4BD-A2DD-A2B5-486DD6EB6315}",
		"GlitchVPN":     "{A7DD3E51-E109-8B19-9263-C9109EB82BF5}",
	} {
		if got := adapterGUID(name).String(); !strings.EqualFold(got, want) {
			t.Errorf("adapterGUID(%q) = %s, want %s", name, got, want)
		}
	}
	if desktopAdapterName != "GlitchVPN" {
		t.Errorf("the desktop adapter is %q, and the vector above is for GlitchVPN", desktopAdapterName)
	}
}

// wifiDirectDescription is the English description the driver gives the adapters
// themselves; the filter interfaces layered on them carry it with a suffix.
var wifiDirectDescription = regexp.MustCompile(`^Microsoft Wi-Fi Direct Virtual Adapter( #\d+)?$`)

// The hotspot's adapters are named by the driver's component, from a key only
// an administrator can change. The driver's own description, which this test
// reads as an oracle and the code never does, says which adapters those are on
// this machine; a machine with none skips.
func TestWifiDirectAdaptersAreFoundByTheirDriversComponent(t *testing.T) {
	adapters, err := allAdapters()
	if err != nil {
		t.Fatal(err)
	}
	wantGUIDs := map[string]bool{}
	wantUp := map[uint32]bool{}
	for _, adapter := range adapters {
		if wifiDirectDescription.MatchString(adapter.Description()) {
			wantGUIDs[strings.ToUpper(adapter.AdapterName())] = true
			if adapter.OperStatus == winipcfg.IfOperStatusUp {
				wantUp[adapter.IfIndex] = true
			}
		}
	}
	if len(wantGUIDs) == 0 {
		t.Skip("no Wi-Fi Direct virtual adapter is installed on this machine")
	}

	guids, err := wifiDirectAdapterGUIDs()
	if err != nil {
		t.Fatalf("the network class's key is not readable: %v", err)
	}
	for guid := range wantGUIDs {
		if !guids[guid] {
			t.Errorf("%s is a Wi-Fi Direct adapter and was not found by its component id", guid)
		}
	}
	for guid := range guids {
		if !wantGUIDs[guid] {
			t.Errorf("%s was found by its component id and is no Wi-Fi Direct adapter", guid)
		}
	}

	up, err := (&windowsHotspotOS{}).HotspotAdapters()
	if err != nil {
		t.Fatalf("HotspotAdapters: %v", err)
	}
	if len(up) != len(wantUp) {
		t.Errorf("HotspotAdapters = %v, want the %d that are up", up, len(wantUp))
	}
	for _, index := range up {
		if !wantUp[index] {
			t.Errorf("interface %d is listed as up and is not", index)
		}
	}
}

// IsUp is the interface's operational state.
func TestIsUpIsTheOperationalState(t *testing.T) {
	adapters, err := allAdapters()
	if err != nil {
		t.Fatal(err)
	}
	os := &windowsHotspotOS{}
	for _, adapter := range adapters {
		if adapter.IfIndex == 0 {
			continue
		}
		if got, want := os.IsUp(adapter.IfIndex), adapter.OperStatus == winipcfg.IfOperStatusUp; got != want {
			t.Errorf("IsUp(%d, %s) = %t, want %t", adapter.IfIndex, adapter.AdapterName(), got, want)
		}
	}
}

// IsPhysical says that an interface exists and is neither the tunnel's nor a
// loopback; whether it is up is not its question.
func TestIsPhysicalIsExistsAndNotTheTunnelOrALoopback(t *testing.T) {
	adapters, err := allAdapters()
	if err != nil {
		t.Fatal(err)
	}
	tunnel := adapterGUID(desktopAdapterName).String()
	os := &windowsHotspotOS{}
	sawLoopback, sawDown := false, false
	for _, adapter := range adapters {
		if adapter.IfIndex == 0 {
			continue
		}
		want := adapter.IfType != winipcfg.IfTypeSoftwareLoopback && !strings.EqualFold(adapter.AdapterName(), tunnel)
		if got := os.IsPhysical(adapter.IfIndex); got != want {
			t.Errorf("IsPhysical(%d, %s, type %d) = %t, want %t", adapter.IfIndex, adapter.AdapterName(), adapter.IfType, got, want)
		}
		sawLoopback = sawLoopback || adapter.IfType == winipcfg.IfTypeSoftwareLoopback
		sawDown = sawDown || adapter.OperStatus != winipcfg.IfOperStatusUp
	}
	if !sawLoopback {
		t.Log("no loopback interface here: that half is not exercised")
	}
	if !sawDown {
		t.Log("no interface that is down here: that half is not exercised")
	}
	for _, index := range []uint32{0, 4000000000} {
		if os.IsPhysical(index) {
			t.Errorf("IsPhysical(%d) is true for an interface that does not exist", index)
		}
	}
}

// Only what names an adapter that is gone is the repair's to touch.
func TestICSRepairTouchesOnlyNamesOfGoneAdapters(t *testing.T) {
	snapshot := icsSnapshot{present: map[string]bool{"{A}": true}}
	if snapshot.namesGoneAdapter("{A}") {
		t.Error("a present adapter was taken for a gone one")
	}
	if !snapshot.namesGoneAdapter("{X}") {
		t.Error("a gone adapter was not found")
	}
}
