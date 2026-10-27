package core

import (
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/logfmt"
)

// engineSession is one engine's view of the session that owns it. Every
// engine keeps the same rules with it:
//
//   - from a start's request until its goroutine ends the engine counts as
//     running, so a stop in that time is taken rather than refused;
//   - a start reports "already running" only for an instance of the current
//     session, and replaces, under coreMutex, one an earlier session left;
//   - a stop leaves an instance started under a generation as new as its own:
//     a start queued behind it brought that one up.
type engineSession struct {
	running        atomic.Bool
	startsInFlight atomic.Int32
	// The session generation the running instance was started under; written
	// under coreMutex.
	instanceGen atomic.Int64
}

// errStopSuperseded: the instance running was started after the stop was
// asked for, by a start queued behind it; the stop leaves it to that session.
var errStopSuperseded = errors.New("a later start owns the engine")

// engaged: running or starting, read without coreMutex, which a start or a
// stop holds for its whole run; callers reach it from a UI thread.
func (s *engineSession) engaged() bool {
	return s.running.Load() || s.startsInFlight.Load() > 0
}

func (s *engineSession) runsSession(gen int64) bool {
	return s.running.Load() && s.instanceGen.Load() == gen
}

func (s *engineSession) supersedes(stopGen int64) bool {
	return s.running.Load() && s.instanceGen.Load() >= stopGen
}

// up marks the instance running for the session at mark. The caller holds
// coreMutex.
func (s *engineSession) up(mark int64) {
	s.instanceGen.Store(mark)
	s.running.Store(true)
}

// beginStart counts a start from its request and copies the platform TUN fd
// there, in the FFI call: by the time the start gets coreMutex the caller may
// have closed that fd and its number gone to something else. done closes the
// copy unless the engine took it, and ends the count, when the start's
// goroutine returns.
func (x *CoreController) beginStart(s *engineSession, tunFd int) (mark int64, tun *tunCopy, done func(), err error) {
	if tun, err = copyRequestTun(tunFd); err != nil {
		return 0, nil, nil, err
	}
	mark = x.sessionGen.Load()
	s.startsInFlight.Add(1)
	return mark, tun, func() {
		tun.release()
		s.startsInFlight.Add(-1)
	}, nil
}

// The dup and close of a start's TUN copy; tests stand in for them, as a dup
// is no copy on Windows.
var (
	dupRequestTun   = dupTunFd
	closeRequestTun = closeTunFd
)

// tunCopy is a start's own copy of the platform TUN fd (fd < 0: none asked
// for). The engine takes it where something else comes to own it.
type tunCopy struct{ fd int }

func copyRequestTun(fd int) (*tunCopy, error) {
	if fd <= 0 {
		return &tunCopy{fd: -1}, nil
	}
	dup, err := dupRequestTun(fd)
	if err != nil {
		return nil, fmt.Errorf("dup TUN fd: %w", err)
	}
	log.Printf("[Generic] dup'd TUN fd %d -> %d", fd, dup)
	return &tunCopy{fd: dup}, nil
}

// take hands the copy over: from here its new owner closes it.
func (t *tunCopy) take() int {
	fd := t.fd
	t.fd = -1
	return fd
}

func (t *tunCopy) release() {
	if t.fd >= 0 {
		closeRequestTun(t.take())
	}
}

// engineStartGate and engineStopGate run before a start or a stop takes
// coreMutex; tests hold them there to order them against each other.
var (
	engineStartGate = func(engine string, mark int64) {}
	engineStopGate  = func(engine string, stopGen int64) {}
)

// abortStaleEngineSession: true when a stop came in after the start at mark,
// whose loops are then torn down - also when the stop already closed the
// instance, as its own cleanup can run before the start armed them. Only a
// later start that replaced the instance owns the loops running now.
func (x *CoreController) abortStaleEngineSession(s *engineSession, mark int64) bool {
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()
	if x.sessionGen.Load() == mark {
		return false
	}
	if !(s.running.Load() && s.instanceGen.Load() > mark) {
		x.endSessionLoops()
	}
	return true
}

// replyAlreadyRunning answers a start of the session already running.
func (x *CoreController) replyAlreadyRunning(label string) int32 {
	x.emitStatus(EngineAlreadyRunning, fmt.Sprintf("[%s] Already running", label))
	x.startStats(time.Second)
	x.emitStatus(EngineConnected, fmt.Sprintf("[%s] Connected (already running)", label))
	x.reemitSessionState()
	return glitchCoreResultSuccess
}

// prepareStartLocked opens an engine's start under coreMutex. errSessionEnded
// when a stop came in before the start took the lock; already when the
// session's own instance runs; an instance an earlier session left is stopped
// with its loops, or this session would report connected on its TUN.
func (x *CoreController) prepareStartLocked(s *engineSession, mark int64, stopLocked func()) (already bool, err error) {
	if x.sessionGen.Load() != mark {
		return false, errSessionEnded
	}
	if s.running.Load() {
		if s.instanceGen.Load() == mark {
			return true, nil
		}
		log.Println("[Generic] replacing the instance of an ended session")
		x.endSessionLoops()
		stopLocked()
	}
	return false, nil
}

// finishStart is the tail of every engine's start goroutine.
func (x *CoreController) finishStart(s *engineSession, label string, mark int64, err error) {
	if errors.Is(err, errSessionEnded) {
		log.Printf("[%s] stopped before startup; not starting", label)
		return
	}
	if err != nil {
		logfmt.Errorf("[%s] Failed to start: %v", label, err)
		x.clearSessionState()
		x.emitStatus(EngineError, fmt.Sprintf("[%s] Failed to start: %v", label, err))
		return
	}
	if x.abortStaleEngineSession(s, mark) {
		log.Printf("[%s] stopped during startup; not publishing connected state", label)
		return
	}
	x.startStats(time.Second)
	x.emitStatus(EngineConnected, fmt.Sprintf("[%s] Connected", label))
}

// stopEngineSession is every engine's stop handler: stop is the engine's own
// stop, given the generation this stop moved the session to.
func (x *CoreController) stopEngineSession(s *engineSession, label string, stop func(stopGen int64) error) int32 {
	if !s.engaged() {
		x.emitStatus(EngineStopRejectedNotRunning, fmt.Sprintf("[%s] Stop rejected: not running", label))
		return glitchCoreResultError
	}
	x.stopStats()
	x.stopLiveness()
	stopGen := x.clearSessionState()
	x.emitStatus(EngineDisconnecting, fmt.Sprintf("[%s] Disconnecting", label))
	go func() {
		err := stop(stopGen)
		if errors.Is(err, errStopSuperseded) {
			log.Printf("[%s] a start after this stop owns the engine; leaving it", label)
			return
		}
		if err != nil {
			logfmt.Errorf("[%s] Failed to stop: %v", label, err)
			x.emitStatus(EngineError, fmt.Sprintf("[%s] Failed to stop: %v", label, err))
			return
		}
		x.emitStatus(EngineDisconnected, fmt.Sprintf("[%s] Disconnected", label))
	}()
	return glitchCoreResultSuccess
}

// stopEngineInstance stops, under coreMutex, the instance a start before
// stopGen brought up.
func (x *CoreController) stopEngineInstance(engine string, s *engineSession, stopGen int64, stopLocked func()) error {
	engineStopGate(engine, stopGen)
	x.coreMutex.Lock()
	defer x.coreMutex.Unlock()
	if s.supersedes(stopGen) {
		return errStopSuperseded
	}
	stopLocked()
	return nil
}
