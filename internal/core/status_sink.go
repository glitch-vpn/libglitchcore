package core

import (
	"slices"
	"sync"
	"sync/atomic"
)

var statusSink atomic.Value

func init() {
	statusSink.Store((func(int32, string))(nil))
}

// setStatusSink registers the one callback every event reaches. It must
// return promptly and never block: events deferred during an FFI call, and
// every event behind them, wait for it on one goroutine, and once
// maxDeferredStatus are waiting the oldest log and connection events go.
func setStatusSink(fn func(int32, string)) {
	if fn == nil {
		statusSink.Store((func(int32, string))(nil))
		statusCallbackRegistered.Store(false)
		return
	}
	statusSink.Store(fn)
	statusCallbackRegistered.Store(true)
}

// deferredStatus delivers the events emitted while an FFI export runs, on its
// own goroutine and in the order they were emitted. While it holds any, later
// events queue behind them, so one sent after the export returns cannot
// overtake one sent during it.
var deferredStatus statusQueue

const maxDeferredStatus = 2048

type statusEvent struct {
	callback func(int32, string)
	code     int32
	message  string
}

type statusQueue struct {
	mu       sync.Mutex
	pending  []statusEvent
	draining bool
}

// offer queues ev when it must not run on the caller's goroutine or when
// events are already queued; false means the caller delivers it now.
func (q *statusQueue) offer(ev statusEvent, mustDefer bool) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !mustDefer && !q.draining {
		return false
	}
	if len(q.pending) >= maxDeferredStatus {
		q.dropOldestDroppable()
	}
	q.pending = append(q.pending, ev)
	if !q.draining {
		q.draining = true
		go q.drain()
	}
	return true
}

// Only traffic events below the error level are shed; lifecycle, stats,
// server and error events stay, and there are few enough of those to keep
// every one.
func (q *statusQueue) dropOldestDroppable() {
	for i, ev := range q.pending {
		if describesTraffic(ev.code) && ev.code != LogError {
			q.pending = append(q.pending[:i], q.pending[i+1:]...)
			return
		}
	}
}

// describesTraffic is true of log and connection events: they name what the
// tunnel carries.
func describesTraffic(code int32) bool {
	return code == LogEvent || code == LogError || code == ConnEvent
}

// dropTrafficEvents discards the queued traffic events, which belong to
// whoever was served when they were emitted.
func (q *statusQueue) dropTrafficEvents() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.pending = slices.DeleteFunc(q.pending, func(ev statusEvent) bool { return describesTraffic(ev.code) })
}

func (q *statusQueue) drain() {
	for {
		q.mu.Lock()
		if len(q.pending) == 0 {
			q.pending = nil
			q.draining = false
			q.mu.Unlock()
			return
		}
		ev := q.pending[0]
		q.pending = q.pending[1:]
		q.mu.Unlock()
		ev.callback(ev.code, ev.message)
	}
}
