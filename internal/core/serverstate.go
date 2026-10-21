package core

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/serverinfo"
)

// GetObservation/Now() read cached health-check state - a short poll is cheap.
var selectionWatchInterval = 5 * time.Second

// Deduped by payload; a mid-session change of the picked server also
// invalidates the external IP.
func (x *CoreController) setServerSelection(sel *serverinfo.Selection) {
	msg, err := sel.JSON()
	if err != nil {
		log.Printf("[server] selection marshal failed: %v", err)
		return
	}
	prev, _ := x.serverSelJSON.Load().(string)
	if prev == msg {
		return
	}
	x.serverSelJSON.Store(msg)
	x.emitStatus(ServerEvent, msg)
	if prev != "" {
		x.triggerIPResolve("server-change")
	}
}

// replaySession re-emits the live session's full view (connected, server/IP
// state) and (re)starts stats - a fresh client restores without connect().
// False when no engine runs in this process.
func (x *CoreController) replaySession() bool {
	id := x.localRunningEngineID()
	if id == "" {
		return false
	}
	x.emitStatus(EngineConnected, fmt.Sprintf("[%s] Connected (already running)", engineDisplayName(id)))
	x.reemitSessionState()
	x.startStats(time.Second)
	return true
}

// For clients attaching to an already-running engine.
func (x *CoreController) reemitSessionState() {
	if s, _ := x.serverSelJSON.Load().(string); s != "" {
		x.emitStatus(ServerEvent, s)
	}
	if s, _ := x.ipStateJSON.Load().(string); s != "" {
		x.emitStatus(IPEvent, s)
	}
}

// errSessionEnded is what an in-process dial captured by a session returns
// once clearSessionState has run for it.
var errSessionEnded = errors.New("session ended")

func (x *CoreController) clearSessionState() {
	x.sessionGen.Add(1)
	x.stopSelectionWatch()
	x.stopIPResolve()
	x.serverSelJSON.Store("")
}

// abortStaleSession: true when a stop tore this session down while it was
// still starting. The stop's cleanup ran before (or during) arming, so undo
// whatever this session armed - on desktop awg a leaked liveness prober would
// otherwise report the physical NIC as the tunnel and publish the user's real
// address as the exit IP.
func (x *CoreController) abortStaleSession(mark int64) bool {
	if x.sessionGen.Load() == mark {
		return false
	}
	x.stopLiveness()
	x.stopSelectionWatch()
	x.stopIPResolve()
	x.serverSelJSON.Store("")
	return true
}

// current returns an index into base.Servers, or -1 for "unknown" - the last
// emitted pick is kept, so transient observatory gaps don't flap.
func (x *CoreController) startSelectionWatch(base serverinfo.Selection, current func() int) {
	x.stopSelectionWatch()
	quit := make(chan struct{})
	done := make(chan struct{})
	x.loopsMu.Lock()
	x.selWatchQuit, x.selWatchDone = quit, done
	x.loopsMu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(selectionWatchInterval)
		defer ticker.Stop()
		last := -1
		for {
			select {
			case <-quit:
				return
			case <-ticker.C:
			}
			idx := current()
			if idx < 0 || idx >= len(base.Servers) || idx == last {
				continue
			}
			last = idx
			sel := base
			s := base.Servers[idx]
			sel.Selected = &s
			x.setServerSelection(&sel)
		}
	}()
}

// Swap the pointers out under the lock, then close and wait outside it, so a
// second concurrent stop finds nil instead of double-closing quit.
func (x *CoreController) stopSelectionWatch() {
	x.loopsMu.Lock()
	quit, done := x.selWatchQuit, x.selWatchDone
	x.selWatchQuit, x.selWatchDone = nil, nil
	x.loopsMu.Unlock()
	if quit == nil {
		return
	}
	close(quit)
	if done != nil {
		<-done
	}
}
