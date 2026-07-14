//go:build android

package core

/*
#include <dlfcn.h>
#include <stdint.h>

// Relax fdsan from FATAL to WARN_ALWAYS (level 2; API 29+). tun2socks
// double-closes the TUN fd (engine.Stop's FD.Close, then gvisor stack.Close ->
// nic.remove -> FD.Close again); between the two the kernel recycles the fd for
// a graphics fence, so the second close trips fdsan and aborts.
static void relax_fdsan() {
    typedef int (*set_error_level_fn)(int);
    set_error_level_fn fn = (set_error_level_fn)dlsym(RTLD_DEFAULT,
        "android_fdsan_set_error_level");
    if (fn) {
        fn(2);
    }
}
*/
import "C"

// Geo is read from the xray.location.asset dir (GeoManager fetches it at
// runtime), not packaged in the APK.
func platformInit(_ string) {
	C.relax_fdsan()
}
