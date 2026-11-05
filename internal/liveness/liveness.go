// Package liveness debounces probe outcomes into an up/down link state.
package liveness

type State int8

const (
	StateUnknown State = iota // no conclusive observation yet
	StateUp
	StateDown
)

func (s State) String() string {
	switch s {
	case StateUp:
		return "up"
	case StateDown:
		return "down"
	default:
		return "unknown"
	}
}

// DefaultDownAfter consecutive failures flip down - a single probe timeout shouldn't.
const DefaultDownAfter = 2

// Tracker: one success -> up immediately; DownAfter consecutive failures -> down.
// The zero value is ready to use.
type Tracker struct {
	DownAfter int // 0 -> DefaultDownAfter

	state State
	fails int
}

func (t *Tracker) State() State { return t.state }

func (t *Tracker) downAfter() int {
	if t.DownAfter > 0 {
		return t.DownAfter
	}
	return DefaultDownAfter
}

func (t *Tracker) ObserveSuccess() (State, bool) {
	t.fails = 0
	changed := t.state != StateUp
	t.state = StateUp
	return t.state, changed
}

func (t *Tracker) ObserveFailure() (State, bool) {
	t.fails++
	if t.fails < t.downAfter() && t.state != StateDown {
		return t.state, false
	}
	changed := t.state != StateDown
	t.state = StateDown
	return t.state, changed
}
