//go:build windows

package core

import (
	"crypto/md5"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
