//go:build no_awg

package core

type awgState struct{}

func (x *CoreController) initEngineState() { x.nextHandle = 1 }
