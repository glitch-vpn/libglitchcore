//go:build windows

package core

import (
	"net/netip"
	"strings"
	"testing"
	"unsafe"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

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

// The hotspot's adapters are named by the driver's component, from a key only
// an administrator can change, and each is an interface that exists.
func TestWifiDirectAdaptersAreFoundByTheirDriversComponent(t *testing.T) {
	guids, err := wifiDirectAdapterGUIDs()
	if err != nil {
		t.Fatalf("the network class's key is not readable: %v", err)
	}
	adapters, err := allAdapters()
	if err != nil {
		t.Fatal(err)
	}
	for guid := range guids {
		found := false
		for _, adapter := range adapters {
			if strings.EqualFold(adapter.AdapterName(), guid) {
				found = true
				if adapter.IfType != winipcfg.IfTypeIEEE80211 {
					t.Errorf("%s is of type %d, not Wi-Fi", guid, adapter.IfType)
				}
			}
		}
		if !found {
			t.Errorf("%s is a Wi-Fi Direct adapter in the registry and no interface", guid)
		}
	}
	up, err := (&windowsHotspotOS{}).HotspotAdapters()
	if err != nil {
		t.Fatalf("HotspotAdapters: %v", err)
	}
	if len(up) > 0 && len(guids) == 0 {
		t.Error("a hotspot adapter was found with no Wi-Fi Direct adapter installed")
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
