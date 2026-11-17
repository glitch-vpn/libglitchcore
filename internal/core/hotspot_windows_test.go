//go:build windows

package core

import (
	"errors"
	"math"
	"net/netip"
	"testing"
	"unsafe"
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

func TestSharedPairFallsBackToTheHotspotServicesRecord(t *testing.T) {
	if _, _, err := sharedPairFromRegistry(); err != nil {
		t.Skipf("the hotspot service's record is not readable here: %v", err)
	}
}

// The tunnel's adapter is found by a GUID its name fixes.
func TestAdapterGUIDIsFixedByTheName(t *testing.T) {
	first, second := adapterGUID(desktopAdapterName), adapterGUID(desktopAdapterName)
	if *first != *second {
		t.Error("the GUID changes between calls")
	}
	if *first == *adapterGUID("Other") {
		t.Error("two names share a GUID")
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

// A pair that cannot be read is not "no hotspot": SharedAccess stays alone.
func TestHotspotRunningIsTrueWhenThePairCannotBeRead(t *testing.T) {
	os := newFakeHotspotOS()
	if !hotspotRunning(os) {
		t.Error("a hotspot on an adapter that is up was not seen")
	}
	os.pairErr = errors.New("unreadable")
	if !hotspotRunning(os) {
		t.Error("an unreadable pair read as no hotspot")
	}
	os.pairErr = nil
	os.public, os.private = math.MaxUint32, math.MaxUint32
	if hotspotRunning(os) {
		t.Error("no pair read as a hotspot")
	}
	os.public, os.private = testWiFi, testGoneIndex
	if hotspotRunning(os) {
		t.Error("a pair on a gone adapter read as a hotspot")
	}
}
