//go:build !android && !linux && !windows

package core

import (
	"os"
	"path/filepath"
)

func platformInit(envPath string) {
	if envPath == "" {
		if exePath, err := os.Executable(); err == nil {
			envPath = filepath.Dir(exePath)
		}
	}
	if envPath != "" {
		setEnvVar(xrayAsset, envPath)
	}
}
