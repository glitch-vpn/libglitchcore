//go:build !windows

package core

import "testing"

func TestHotspotAnswersUnsupportedOffWindows(t *testing.T) {
	if got := PrepareHotspot(); got != hotspotResultUnsupported {
		t.Errorf("PrepareHotspot() = %d, want %d", got, hotspotResultUnsupported)
	}
	if got := SetHotspotSharing(`{"on":true}`); got != hotspotResultUnsupported {
		t.Errorf("SetHotspotSharing() = %d, want %d", got, hotspotResultUnsupported)
	}
}
