package core

import "runtime"

var useServiceIPC = runtime.GOOS == "windows" && !buildModeService
