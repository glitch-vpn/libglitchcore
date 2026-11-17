//go:build !windows

package core

const hotspotSupported = false

func newHotspotOS() hotspotOS { return nil }

func prepareHotspot() int32 { return hotspotResultUnsupported }
