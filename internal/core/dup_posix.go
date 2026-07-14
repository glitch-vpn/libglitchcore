//go:build !windows

package core

import "syscall"

// dupTunFd gives the engine its own copy of the TUN fd to close on teardown:
// sing-tun/tun2socks close the fd they're handed, and without the dup that's the
// platform's fd (Android PFD / iOS NE), which trips fdsan and aborts.
func dupTunFd(fd int) (int, error) { return syscall.Dup(fd) }
