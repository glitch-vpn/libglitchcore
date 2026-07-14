//go:build !android && !linux && !windows && !no_awg

package core

import "errors"

func (x *CoreController) platformAwgStart(ifName string, tunFd int, settings string) (int, error) {
	return -1, errors.New("turning on from file descriptor is not supported on this platform")
}
