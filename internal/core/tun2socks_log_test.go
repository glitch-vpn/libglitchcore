//go:build !no_xray || (!no_mihomo && !no_awg)

package core

import (
	"testing"

	tun2socksLog "github.com/xjasonlyu/tun2socks/v2/log"
	"go.uber.org/zap"
)

func TestTun2socksSink_KeepsZapLevelUnderTheKeyLevel(t *testing.T) {
	logs := captureLogs(t, 2)
	t.Cleanup(func() { tun2socksLog.SetLogger(zap.NewNop()) })

	useTun2socksSink("warn")
	tun2socksLog.Debugf("[TCP] %s <-> %s", "a", "b")
	tun2socksLog.Infof("[STACK] tun://x <-> socks5://127.0.0.1:1080")
	tun2socksLog.Warnf("[UDP] dial %s: %v", "1.2.3.4:53", "timeout")
	tun2socksLog.Errorf("[TUN] failed to post-execute")

	want := []capturedLog{
		{LogEvent, "warn", "tun2socks", "[UDP] dial 1.2.3.4:53: timeout"},
		{LogError, "error", "tun2socks", "[TUN] failed to post-execute"},
	}
	assertLogs(t, logs(), want)

	useTun2socksSink("silent")
	tun2socksLog.Errorf("[TUN] dropped")
	if n := len(logs()); n != len(want) {
		t.Errorf("a silent key level still delivered %d lines", n-len(want))
	}
}
