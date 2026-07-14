//go:build !linux && !windows

package core

func currentProcessRSSBytes() uint64 { return 0 }

func currentProcessHandleCount() uint32 { return 0 }
