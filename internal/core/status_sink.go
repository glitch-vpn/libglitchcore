package core

import "sync/atomic"

var statusSink atomic.Value

func init() {
	statusSink.Store((func(int32, string))(nil))
}

func setStatusSink(fn func(int32, string)) {
	if fn == nil {
		statusSink.Store((func(int32, string))(nil))
		statusCallbackRegistered.Store(false)
		return
	}
	statusSink.Store(fn)
	statusCallbackRegistered.Store(true)
}
