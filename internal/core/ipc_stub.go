//go:build !windows || service

package core

import "time"

func ensureServiceIPC() {}

// Engine IPC forwarders - no-ops off Windows and in the service (useServiceIPC
// is false there); they exist only to satisfy the shared engineStart references.
func serviceEngineStart(id string, req EngineStartRequest) error { return nil }

func serviceEngineStop(id string) error { return nil }

func serviceEngineStatus(id string) (bool, error) { return false, nil }

func serviceSetVerbosity(level int) error { return nil }

func serviceSetConnInspector(enabled bool) error { return nil }

func serviceSetMemoryLimit(bytes int64) error { return nil }

func serviceListenStats(interval time.Duration) error { return nil }

func serviceStopStats() error { return nil }
