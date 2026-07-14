package core

import (
	"log"
	"math"
	"runtime/debug"
)

// noMemoryLimit is debug.SetMemoryLimit's "unlimited" sentinel.
const noMemoryLimit = math.MaxInt64

// applyMemoryLimit sets a soft heap cap (GC pressure as it nears the limit, not
// an OOM-kill guard); bytes<=0 = unlimited. Forwarded to the service in Windows
// library mode, where the engine actually runs.
func applyMemoryLimit(bytes int64) {
	if useServiceIPC {
		if err := serviceSetMemoryLimit(bytes); err != nil {
			log.Printf("[mem] service set memory limit failed: %v", err)
		}
		return
	}
	limit := int64(noMemoryLimit)
	if bytes > 0 {
		limit = bytes
	}
	debug.SetMemoryLimit(limit)
	if bytes > 0 {
		log.Printf("[mem] soft memory limit set to %d bytes", bytes)
	} else {
		log.Printf("[mem] soft memory limit disabled (unlimited)")
	}
}
