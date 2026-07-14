//go:build android

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// "rx,tx" decimal bytes ("" when idle). Caller must free(). Plain C types only -
// <jni.h> in a cgo //export preamble would leak into libglitchcore.h and break ffigen.
//
//export glitchEngineTraffic
func glitchEngineTraffic() *C.char {
	out := ""
	if rx, tx, running := core.EngineTraffic(); running {
		out = fmt.Sprintf("%d,%d", rx, tx)
	}
	return C.CString(out)
}
