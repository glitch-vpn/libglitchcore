package core

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof handlers on DefaultServeMux
	"net/netip"
	"os"
	"runtime"
	"sync"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
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
	if err := checkPprofListenAddr(addr); err != nil {
		logfmt.Errorf("[pprof] GLITCH_PPROF_ADDR: %v", err)
		return
	}
	pprofOnce.Do(func() {
		runtime.SetBlockProfileRate(1)
		runtime.SetMutexProfileFraction(1)
		go func() {
			log.Printf("[pprof] listening on http://%s/debug/pprof/", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				logfmt.Errorf("[pprof] server error: %v", err)
			}
		}()
	})
}

// checkPprofListenAddr accepts a loopback host:port only: the profiler serves
// heap and goroutine dumps of the engine's process to whoever reaches it.
func checkPprofListenAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("host must be localhost or a loopback IP")
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%s is not a loopback address", ip)
	}
	return nil
}
