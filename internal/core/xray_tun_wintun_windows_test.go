//go:build windows && !no_xray && !with_tun2socks && with_gvisor

package core

import (
	"errors"
	"net"
	"testing"

	"golang.zx2c4.com/wintun"
)

// xray-core links golang.zx2c4.com/wintun through its own TUN, WireGuard and
// masque packages, which no config the core builds uses. The main variant
// builds third_party/wintun's stub there, so only sing-tun's binding can load
// a wintun.dll: two bindings would fight over the adapter's name.
func TestXrayWintunBinding_IsTheRefusingStub(t *testing.T) {
	if _, err := wintun.CreateAdapter("glitch-stub-check", "Wintun", nil); !errors.Is(err, wintun.ErrNotSupported) {
		t.Fatalf("CreateAdapter err = %v, want wintun.ErrNotSupported", err)
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
