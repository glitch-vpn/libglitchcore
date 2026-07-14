//go:build windows

package core

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// processMemoryCounters mirrors PROCESS_MEMORY_COUNTERS (psapi.h) - x/sys/windows
// doesn't export GetProcessMemoryInfo. Field order must match the C struct.
type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

var (
	modPsapi                 = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = modPsapi.NewProc("GetProcessMemoryInfo")

	modKernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procGetProcessHandleCount = modKernel32.NewProc("GetProcessHandleCount")
)

// currentProcessHandleCount returns the open handle count (sockets included); a
// monotonic rise over a long session points at a leak. 0 if unavailable.
func currentProcessHandleCount() uint32 {
	var count uint32
	r, _, _ := procGetProcessHandleCount.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&count)),
	)
	if r == 0 {
		return 0
	}
	return count
}

// currentProcessRSSBytes returns the working set (Windows' RSS analogue).
func currentProcessRSSBytes() uint64 {
	var pmc processMemoryCounters
	pmc.cb = uint32(unsafe.Sizeof(pmc))
	r, _, _ := procGetProcessMemoryInfo.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&pmc)),
		uintptr(pmc.cb),
	)
	if r == 0 {
		return 0
	}
	return uint64(pmc.workingSetSize)
}
