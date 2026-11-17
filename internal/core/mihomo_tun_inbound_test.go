//go:build !no_mihomo

package core

import (
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

const tunInboundTestLink = "vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?type=tcp&security=none#t"

// With no fd the core creates the adapter, and the MTU and UDP timeout the app
// set (SetTun2SocksConfig) reach mihomo's TUN as they reached the bridge.
func TestMihomoTunInbound_AdapterTakesTheUserSettings(t *testing.T) {
	t.Setenv("GLITCH_TUN2SOCKS_MTU", "1380")
	t.Setenv("GLITCH_TUN2SOCKS_UDP_TIMEOUT_SEC", "45")
	tin := mihomoTunInbound(dnsconfig.Config{}, -1)
	if tin.Device != mihomoDesktopAdapterName || tin.FileDescriptor != 0 {
		t.Fatalf("device %q, fd %d, want the desktop adapter and no fd", tin.Device, tin.FileDescriptor)
	}
	if tin.MTU != 1380 || tin.UDPTimeoutSec != 45 {
		t.Fatalf("mtu %d, udp timeout %d, want the settings 1380 and 45", tin.MTU, tin.UDPTimeoutSec)
	}
	if !tin.ProcessFirst {
		t.Fatal("the adapter's process rules do not lead")
	}
}

func TestMihomoTunInbound_AdapterDefaultsMatchTheBridge(t *testing.T) {
	t.Setenv("GLITCH_TUN2SOCKS_MTU", "")
	t.Setenv("GLITCH_TUN2SOCKS_UDP_TIMEOUT_SEC", "")
	tin := mihomoTunInbound(dnsconfig.Config{}, -1)
	if tin.MTU != defaultTunMTU || tin.UDPTimeoutSec != defaultTunUDPTimeoutSec {
		t.Fatalf("mtu %d, udp timeout %d, want %d and %d", tin.MTU, tin.UDPTimeoutSec, defaultTunMTU, defaultTunUDPTimeoutSec)
	}
}

// A platform's fd is left as the platform set it up: the user's settings and
// the process-first order belong to the adapter the core creates.
func TestMihomoTunInbound_PlatformFdIsLeftAlone(t *testing.T) {
	t.Setenv("GLITCH_TUN2SOCKS_MTU", "1380")
	t.Setenv("GLITCH_TUN2SOCKS_UDP_TIMEOUT_SEC", "45")
	tin := mihomoTunInbound(dnsconfig.Config{}, 42)
	if tin.FileDescriptor != 42 || tin.Device != "" {
		t.Fatalf("fd %d, device %q, want the fd alone", tin.FileDescriptor, tin.Device)
	}
	if tin.MTU != defaultTunMTU || tin.UDPTimeoutSec != 0 || tin.ProcessFirst {
		t.Fatalf("mtu %d, udp timeout %d, process first %v, want the defaults", tin.MTU, tin.UDPTimeoutSec, tin.ProcessFirst)
	}
}

// The adapter's TUN is mihomo's own on every platform: auto-routed, with its
// outbounds bound to the physical interface (so the servers stay off the TUN),
// :53 hijacked to mihomo's resolver and an echo request dropped.
func TestMihomoTunInbound_BuildsANativeTunThatKeepsServersOff(t *testing.T) {
	t.Setenv("GLITCH_TUN2SOCKS_MTU", "1380")
	t.Setenv("GLITCH_TUN2SOCKS_UDP_TIMEOUT_SEC", "45")
	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{dnsconfig.DefaultResolver}}
	mihomoTestHome(t)
	cfg, err := mihomoconfig.BuildConfig([]string{tunInboundTestLink}, mihomoconfig.Inbound{Tun: mihomoTunInbound(dns, -1)}, mihomoconfig.Options{}, routing.Profile{})
	if err != nil {
		t.Fatal(err)
	}
	tun := cfg.General.Tun
	if !tun.Enable || tun.Device != mihomoDesktopAdapterName {
		t.Errorf("tun enabled %v on %q, want the desktop adapter", tun.Enable, tun.Device)
	}
	if !tun.AutoRoute || !tun.AutoDetectInterface {
		t.Errorf("auto-route %v, auto-detect-interface %v: the servers would loop into the TUN", tun.AutoRoute, tun.AutoDetectInterface)
	}
	if len(tun.DNSHijack) != 1 || tun.DNSHijack[0] != "any:53" {
		t.Errorf("dns hijack %v, want any:53", tun.DNSHijack)
	}
	if !tun.DisableICMPForwarding {
		t.Error("an echo request leaves the tunnel")
	}
	if tun.MTU != 1380 || tun.UDPTimeout != 45 {
		t.Errorf("mtu %d, udp timeout %d, want 1380 and 45", tun.MTU, tun.UDPTimeout)
	}
	if cfg.DNS.EnhancedMode.String() != "fake-ip" {
		t.Errorf("dns mode %s, want fake-ip", cfg.DNS.EnhancedMode)
	}
	if cfg.General.Interface != "" {
		t.Errorf("interface %q pinned: auto-detect owns the physical interface", cfg.General.Interface)
	}
}
