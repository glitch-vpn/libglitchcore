//go:build windows && !no_xray && with_tun2socks

package core

import (
	"crypto/md5"
	"unsafe"

	"golang.org/x/sys/windows"
	wintunTun "golang.zx2c4.com/wireguard/tun"
)

// The bridge's Wintun binding sets the adapter's description ("tun2socks
// Tunnel") in its init and lets Wintun draw a GUID at random; the adapter's
// name comes from the device URI (tun://GlitchVPN). This init runs after it
// and gives the adapter sing-tun's description and GUID.
func init() {
	wintunTun.WintunTunnelType = desktopTunnelType
	wintunTun.WintunStaticRequestedGUID = adapterGUID(desktopAdapterName)
}

// adapterGUID is a second copy of the sing-tun fork's generateGUIDByDeviceName
// (tun_windows.go), which is unexported. A change to either moves only its own
// adapter's GUID, so the two must change together.
func adapterGUID(name string) *windows.GUID {
	hash := md5.New()
	hash.Write([]byte("wintun"))
	hash.Write([]byte(name))
	sum := hash.Sum(nil)
	return (*windows.GUID)(unsafe.Pointer(&sum[0]))
}
