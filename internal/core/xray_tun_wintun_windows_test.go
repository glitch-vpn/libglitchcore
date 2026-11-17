//go:build windows && !no_xray && !with_tun2socks && with_gvisor

package core

import (
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// xray-core links golang.zx2c4.com/wintun through its own TUN, WireGuard and
// masque packages, which no config the core builds uses. Only sing-tun's
// embedded binding drives an adapter, so the library on disk is never
// loaded: were it loaded beside sing-tun's, the two would fight over the
// adapter's name.
func TestXrayTun_NeverLoadsTheWintunLibraryOnDisk(t *testing.T) {
	prof := routing.Profile{Mode: routing.ModeDirectAll}
	rig := startTunRig(t, startTunInstance(t, prof, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, 0, tcpEcho(t)), prof, tunTestMTU, nil)
	conn, err := rig.dialTCP(t, 80)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	requireTunEcho(t, conn, []byte("ping"))

	name, err := windows.UTF16PtrFromString("wintun.dll")
	if err != nil {
		t.Fatal(err)
	}
	var module windows.Handle
	err = windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, name, &module)
	if !errors.Is(err, windows.ERROR_MOD_NOT_FOUND) {
		t.Fatalf("wintun.dll is loaded in the process (module %#x, err %v)", module, err)
	}
}

// Direct egress binds the NIC the default route leaves by, and the address on
// it, before the adapter exists.
func TestXrayDirectEgress_NamesTheDefaultRoutesInterface(t *testing.T) {
	iface, sendThrough := xrayDirectEgress()
	if iface == "" {
		t.Skip("no default route on this machine")
	}
	if sendThrough == "" {
		t.Fatalf("interface %q has no IPv4 address to send through", iface)
	}
	found := false
	nic, err := netInterfaceByName(iface)
	if err != nil {
		t.Fatalf("interface %q: %v", iface, err)
	}
	for _, address := range nic {
		if address == sendThrough {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s is not an address of %q (%v)", sendThrough, iface, nic)
	}
}

func netInterfaceByName(name string) ([]string, error) {
	nic, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := nic.Addrs()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			out = append(out, ipnet.IP.String())
		}
	}
	return out, nil
}
