// Android-only (compiled solely for GOOS=android via the _android.c filename
// suffix). JNI wrapper for the notification stats read.
//
// This lives in a .c file rather than a Go cgo preamble so that <jni.h> never
// reaches the cgo-generated C header (libglitchcore.h): a //export function's
// preamble is copied verbatim into that header, and dragging jni.h in there
// makes ffigen try to bind all of jni.h (a 250k-line, broken output). The Go
// side (notif_stats_android.go) exposes only plain C types.

#include <jni.h>
#include <stdlib.h>

// Defined in Go via //export glitchEngineTraffic. Returns a malloc'd "rx,tx"
// (decimal bytes) or "", which we must free().
extern char *glitchEngineTraffic(void);

// com.glitch_vpn.core.GlitchVpnService.nativeEngineTraffic(): String
//
// The `1` in glitch_1vpn is the JNI mangling of the underscore in the package
// name com.glitch_vpn.core. JNIEXPORT forces default symbol visibility so the
// JVM's dynamic lookup finds this in libglitchcore.so.
JNIEXPORT jstring JNICALL
Java_com_glitch_1vpn_core_GlitchVpnService_nativeEngineTraffic(JNIEnv *env, jobject thiz) {
    (void)thiz;
    char *s = glitchEngineTraffic();
    jstring r = (*env)->NewStringUTF(env, s ? s : "");
    if (s) {
        free(s);
    }
    return r;
}
