package core

import (
	"log"
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof handlers on DefaultServeMux
	"os"
	"runtime"
	"sync"
)

var pprofOnce sync.Once

// maybeStartPprof starts a loopback pprof server when GLITCH_PPROF_ADDR is set.
// It runs in the engine-hosting process (the service on Windows-release), so the
// live engine can be profiled for leaks.
func maybeStartPprof() {
	addr := os.Getenv("GLITCH_PPROF_ADDR")
	if addr == "" {
		return
	}
	pprofOnce.Do(func() {
		runtime.SetBlockProfileRate(1)
		runtime.SetMutexProfileFraction(1)
		go func() {
			log.Printf("[pprof] listening on http://%s/debug/pprof/", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				log.Printf("[pprof] server error: %v", err)
			}
		}()
	})
}
