//go:build !no_awg

package awgconfig

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// The UAPI ParseToUAPI writes has to be what the linked amneziawg-go reads:
// the device refuses a whole set over one key it does not know.
func TestParseToUAPI_AcceptedByDevice(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg  string
		want []string
	}{
		"legacy": {legacyAwgConfig, []string{"s2=39", "h4=1794200446", "persistent_keepalive_interval=25"}},
		"awg3": {awg3Config, []string{
			"s4=23", "i1=<b 0xc30000000108><rc 8><t>", "content_padding_addition=0-64",
			"rekey_after_time=110-130", "max_handshake_attempts=15-20", "persistent_keepalive_interval=22-30",
		}},
	} {
		t.Run(name, func(t *testing.T) {
			uapi, err := ParseToUAPI(tc.cfg)
			if err != nil {
				t.Fatalf("ParseToUAPI: %v", err)
			}
			tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.10.0.2")}, nil, 1420)
			if err != nil {
				t.Fatalf("netstack: %v", err)
			}
			dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
			defer dev.Close()

			if err := dev.IpcSet(uapi); err != nil {
				t.Fatalf("IpcSet: %v\n%s", err, uapi)
			}
			got, err := dev.IpcGet()
			if err != nil {
				t.Fatalf("IpcGet: %v", err)
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want+"\n") {
					t.Errorf("device state lacks %q:\n%s", want, got)
				}
			}
		})
	}
}
