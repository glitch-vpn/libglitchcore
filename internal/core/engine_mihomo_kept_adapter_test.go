//go:build !no_mihomo

package core

import (
	"strings"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
)

// mihomo's native TUN asks the fork's New for the adapter by this name, which
// is the name the keeper keeps: a different one would make every mihomo
// session create its own beside the kept adapter.
func TestMihomoNativeTun_AsksForTheKeptAdapterByItsName(t *testing.T) {
	inbound := mihomoTunInbound(dnsconfig.Config{}, -1)
	if !strings.EqualFold(inbound.Device, desktopAdapterName) {
		t.Fatalf("mihomo's TUN device is %q, the keeper keeps %q", inbound.Device, desktopAdapterName)
	}
}
