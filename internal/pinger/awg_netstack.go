//go:build no_mihomo && !no_awg

package pinger

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"

	"github.com/glitch-vpn/libglitchcore/internal/awgconfig"
)

// In-memory userspace WG stack when mihomo isn't linked - no TUN, no admin.
func measureAwgNetstack(ctx context.Context, link, probeURL string) (time.Duration, error) {
	ini, err := awgconfig.NormalizeToINI(link)
	if err != nil {
		return 0, err
	}
	uapi, err := awgconfig.ParseToUAPI(ini)
	if err != nil {
		return 0, err
	}
	addrs := parseAddrCSV(awgconfig.Address(ini))
	if len(addrs) == 0 {
		return 0, fmt.Errorf("no interface address in config")
	}
	dns := parseAddrCSV(awgconfig.DNS(ini))
	if len(dns) == 0 {
		dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}

	tunDev, tnet, err := netstack.CreateNetTUN(addrs, dns, 1420)
	if err != nil {
		return 0, fmt.Errorf("netstack tun: %w", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.IpcSet(uapi); err != nil {
		return 0, fmt.Errorf("uapi: %w", err)
	}
	if err := dev.Up(); err != nil {
		return 0, fmt.Errorf("device up: %w", err)
	}
	return probe(ctx, probeURL, tnet.DialContext)
}

func parseAddrCSV(s string) []netip.Addr {
	var out []netip.Addr
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if p, err := netip.ParsePrefix(part); err == nil {
			out = append(out, p.Addr())
		} else if a, err := netip.ParseAddr(part); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func init() {
	registerMeasurer(engineMeasurer{
		engine:  "awg",
		match:   matchAwgLink,
		measure: measureAwgNetstack,
	})
}
