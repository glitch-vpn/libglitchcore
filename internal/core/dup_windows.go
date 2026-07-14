//go:build windows

package core

// dupTunFd is a no-op on Windows - the TUN there is a Wintun adapter, not an fd,
// so there is nothing to duplicate.
func dupTunFd(fd int) (int, error) { return fd, nil }
