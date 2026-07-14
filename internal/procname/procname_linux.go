//go:build linux

package procname

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
)

func findProcessName(tcp bool, src netip.Addr, port uint16) (string, error) {
	var inode uint64
	for _, name := range procNetFiles(tcp, src.Is6()) {
		data, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		if inode = findSocketInode(string(data), src, port); inode != 0 {
			break
		}
	}
	if inode == 0 {
		return "", ErrNotFound
	}
	pid, err := pidForInode(inode)
	if err != nil {
		return "", err
	}
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return "", fmt.Errorf("readlink exe of pid %d: %w", pid, err)
	}
	return exe, nil
}

// v4 sockets of dual-stack binds live in the v6 table (v4-mapped or ::).
func procNetFiles(tcp, v6 bool) []string {
	base := "/proc/net/udp"
	if tcp {
		base = "/proc/net/tcp"
	}
	if v6 {
		return []string{base + "6"}
	}
	return []string{base, base + "6"}
}

// Needs enough privilege to read other processes' fd tables; the VPN process
// has it (it created the TUN).
func pidForInode(inode uint64) (int, error) {
	target := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, d := range entries {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		fdDir := "/proc/" + d.Name() + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if link, err := os.Readlink(fdDir + "/" + fd.Name()); err == nil && link == target {
				return pid, nil
			}
		}
	}
	return 0, ErrNotFound
}
