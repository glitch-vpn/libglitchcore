//go:build linux

package core

import (
	"os"
	"strconv"
	"strings"
)

// currentProcessRSSBytes reads VmRSS from /proc/self/status (covers Android too -
// GOOS=android sets the linux build tag).
func currentProcessRSSBytes() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "VmRSS:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest) // "12345 kB"
		if len(fields) >= 1 {
			if kb, perr := strconv.ParseUint(fields[0], 10, 64); perr == nil {
				return kb * 1024
			}
		}
		return 0
	}
	return 0
}

// currentProcessHandleCount counts /proc/self/fd (sockets included); a monotonic
// rise points at an fd/socket leak.
func currentProcessHandleCount() uint32 {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return uint32(len(entries))
}
