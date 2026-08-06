package core

import "os"

// Guarded by coreMutex - only the engine start bodies touch them, and only
// one engine runs at a time.
var (
	geoAssetsOverridden bool
	geoAssetsSaved      string
)

// applyGeoAssetsDir points xray's lazy geo loading (os.Getenv at cfg.Build
// time) at the caller-supplied dir for this connection. An empty dir restores
// the pre-override value, so a custom dir from a previous session cannot leak
// into one that omits the opt. The snapshot is restored rather than re-running
// platformInit because on Android the default is whatever the app put into the
// env via SetEnvVar, not the executable dir.
func applyGeoAssetsDir(dir string) {
	if dir == "" {
		if geoAssetsOverridden {
			setEnvVar(xrayAsset, geoAssetsSaved)
			geoAssetsOverridden = false
			geoAssetsSaved = ""
		}
		return
	}
	if !geoAssetsOverridden {
		geoAssetsSaved = os.Getenv(xrayAsset)
		geoAssetsOverridden = true
	}
	setEnvVar(xrayAsset, dir)
}
