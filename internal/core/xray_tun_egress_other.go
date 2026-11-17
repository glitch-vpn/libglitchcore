//go:build !no_xray && !with_tun2socks && !windows

package core

// xrayDirectEgress is empty off Windows: the platform keeps the engine's own
// sockets outside the TUN (VpnService excludes the app on Android).
func xrayDirectEgress() (iface, sendThrough string) { return "", "" }
