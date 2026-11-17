//go:build windows && !no_xray && with_tun2socks

package core

import (
	"crypto/md5"
	"unsafe"

	"golang.org/x/sys/windows"
	wintunTun "golang.zx2c4.com/wireguard/tun"
)

// The bridge's Wintun binding names its adapter "tun2socks" in its init and
// lets Wintun draw a GUID at random. This init runs after it and gives the
// adapter sing-tun's identity: its tunnel type, and the GUID sing-tun derives
// from the name (sing-tun's generateGUIDByDeviceName; a change there moves
// both).
func init() {
	wintunTun.WintunTunnelType = desktopTunnelType
	wintunTun.WintunStaticRequestedGUID = adapterGUID(desktopAdapterName)
}

func adapterGUID(name string) *windows.GUID {
	hash := md5.New()
	hash.Write([]byte("wintun"))
	hash.Write([]byte(name))
	sum := hash.Sum(nil)
	return (*windows.GUID)(unsafe.Pointer(&sum[0]))
}
