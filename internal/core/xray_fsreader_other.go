//go:build !no_xray && !android && !linux && !windows

package core

import (
	"io"
	"os"

	corefilesystem "github.com/xtls/xray-core/common/platform/filesystem"
)

// xray-core has no bundled-asset reader on non-standard GOOS; point it at the
// filesystem so it reads geo from the xray.location.asset dir.
func init() {
	corefilesystem.NewFileReader = func(path string) (io.ReadCloser, error) {
		return os.Open(path)
	}
}
