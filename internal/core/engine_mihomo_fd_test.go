//go:build linux && !no_mihomo

package core

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The TUN fd stands in as a pipe's read end: once the caller closes its own
// copy, a write fails with EPIPE only if no dup of it is left open.
func TestMihomoStart_FailedStartClosesTunDup(t *testing.T) {
	cases := []struct {
		name   string
		links  []string
		geoDir func(t *testing.T) string
	}{
		{
			name:   "no home dir",
			links:  []string{"hysteria2://secret@127.0.0.1:443#test"},
			geoDir: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
		},
		{
			name:   "config build",
			links:  []string{"unknown://127.0.0.1:443"},
			geoDir: func(t *testing.T) string { return t.TempDir() },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			platformFd, writeEnd, err := os.Pipe()
			if err != nil {
				t.Fatalf("pipe: %v", err)
			}
			defer writeEnd.Close()

			t.Cleanup(func() { applyGeoAssetsDir("") })
			x := &CoreController{}
			startErr := x.mihomoStart(tc.links, int(platformFd.Fd()), engineOpts{geoAssetsDir: tc.geoDir(t)}, x.sessionGen.Load())
			if startErr == nil {
				t.Fatal("mihomoStart succeeded, want a failed start")
			}
			platformFd.Close()

			if _, err := writeEnd.Write([]byte{0}); !errors.Is(err, syscall.EPIPE) {
				t.Errorf("after %v: write to the pipe = %v, want EPIPE: the TUN dup is still open", startErr, err)
			}
		})
	}
}
