//go:build windows

package procname

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi       = windows.NewLazySystemDLL("iphlpapi.dll")
	getExtendedTCP = iphlpapi.NewProc("GetExtendedTcpTable")
	getExtendedUDP = iphlpapi.NewProc("GetExtendedUdpTable")
)

// TCP_TABLE_OWNER_PID_ALL / UDP_TABLE_OWNER_PID
const (
	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
)

func findProcessName(tcp bool, src netip.Addr, port uint16) (string, error) {
	family := uint32(windows.AF_INET)
	if src.Is6() {
		family = windows.AF_INET6
	}
	proc, class := getExtendedUDP, uintptr(udpTableOwnerPid)
	if tcp {
		proc, class = getExtendedTCP, uintptr(tcpTableOwnerPidAll)
	}
	table, err := fetchTable(proc, family, class)
	if err != nil {
		return "", err
	}
	pid, ok := matchPid(table, layoutFor(tcp, src.Is6()), src, port)
	if !ok {
		return "", ErrNotFound
	}
	return pidExePath(pid)
}

func fetchTable(proc *windows.LazyProc, family uint32, class uintptr) ([]byte, error) {
	var size uint32
	var buf []byte
	// The table can grow between the sizing call and the fetch; retry a few times.
	for i := 0; i < 4; i++ {
		var p unsafe.Pointer
		if len(buf) > 0 {
			p = unsafe.Pointer(&buf[0])
		}
		ret, _, _ := proc.Call(uintptr(p), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), class, 0)
		switch ret {
		case 0:
			return buf[:size], nil
		case uintptr(windows.ERROR_INSUFFICIENT_BUFFER):
			buf = make([]byte, size)
		default:
			return nil, fmt.Errorf("iphlpapi table query: error %d", ret)
		}
	}
	return nil, fmt.Errorf("iphlpapi table size kept changing")
}

func pidExePath(pid uint32) (string, error) {
	if pid == 0 || pid == 4 {
		return "", fmt.Errorf("pid %d is system-owned", pid)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("open pid %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", fmt.Errorf("image name of pid %d: %w", pid, err)
	}
	return windows.UTF16ToString(buf[:size]), nil
}
