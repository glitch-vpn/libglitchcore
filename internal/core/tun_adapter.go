package core

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// logTunStep writes how long one step of the TUN layer's start or stop took,
// so a slow connect or disconnect shows which step spent the time.
func logTunStep(step string, started time.Time) {
	log.Printf("[tun] %s in %dms", step, time.Since(started).Milliseconds())
}

// desktopAdapterName names the TUN the core creates on a desktop, for every
// engine and both TUN layers. The adapter's GUID derives from the name, so
// one name is the one network identity Windows keeps for the VPN. Linux
// limits an interface name to 15 characters.
const desktopAdapterName = "GlitchVPN"

// desktopTunnelType is the adapter's description on Windows, "<type> Tunnel",
// and the label of the firewall filters sing-tun installs for it.
const desktopTunnelType = "Glitch VPN"

// desktopAdapterGate serialises the desktop adapter's lifetimes: the keeper's
// create, and each session's use. Every engine and both TUN layers use one
// name and so one GUID: a session started while the last one's Close was still
// running would share the adapter with it, and a create while another's Close
// was removing it would find the name half gone. A stop gives up waiting for
// its Close after a few seconds and the Close carries on, so the gate is
// released by the Close returning, not by the stop returning.
var desktopAdapterGate adapterGate

// desktopAdapterWait bounds how long a start waits for the previous
// session's Close or the keeper's create.
var desktopAdapterWait = 30 * time.Second

type adapterGate struct {
	mu   sync.Mutex
	held chan struct{} // closed when the holder's adapter is gone; nil when free
}

// claim returns once no adapter is held, then holds the gate until release.
// release is safe to call more than once. A holder calls release after its
// adapter's Close has returned, or at once when it never created one.
func (g *adapterGate) claim(wait time.Duration) (release func(), err error) {
	timeout := time.NewTimer(wait)
	defer timeout.Stop()
	for {
		g.mu.Lock()
		if g.held == nil {
			mine := make(chan struct{})
			g.held = mine
			g.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					g.mu.Lock()
					g.held = nil
					g.mu.Unlock()
					close(mine)
				})
			}, nil
		}
		previous := g.held
		g.mu.Unlock()
		select {
		case <-previous:
		case <-timeout.C:
			return nil, fmt.Errorf("the %s adapter is still in use: the previous session is closing or it is being created", desktopAdapterName)
		}
	}
}

// releaseDesktopAdapter frees the gate for the adapter the controller holds,
// once that adapter is gone. The caller holds coreMutex.
func (x *CoreController) releaseDesktopAdapter() {
	if x.desktopAdapterRelease != nil {
		x.desktopAdapterRelease()
		x.desktopAdapterRelease = nil
	}
}
