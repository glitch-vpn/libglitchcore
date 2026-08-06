package core

import (
	"os"
	"testing"
)

// Windows client builds default useServiceIPC to true, so an engine or stats
// call from a test binary would reach the user's live GlitchVpnCore service.
func TestMain(m *testing.M) {
	SetServiceIPC(false)
	os.Exit(m.Run())
}
