//go:build !no_xray

package core

import (
	"strings"
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
		{LogEvent, "warn", "tun2socks", "[UDP] dial <addr>: timeout"},
		{LogError, "error", "tun2socks", "[TUN] failed to post-execute"},
	}
	assertLogs(t, logs(), want)

	useTun2socksSink("silent")
	tun2socksLog.Errorf("[TUN] dropped")
	if n := len(logs()); n != len(want) {
		t.Errorf("a silent key level still delivered %d lines", n-len(want))
	}
}

// A dial tun2socks could not make is logged with its destination, and a
// refused direct app's flow is one such dial: the line reaches the shareable
// log with every address taken out, and the refusal names nothing itself.
func TestTun2socksSink_KeepsARefusedFlowsDestinationOut(t *testing.T) {
	logs := captureLogs(t, 2)
	t.Cleanup(func() { tun2socksLog.SetLogger(zap.NewNop()) })
	useTun2socksSink("warn")

	tun2socksLog.Warnf("[TCP] dial %s: %v", "198.18.0.7:443", errProcessBlocked)
	for _, refusal := range []string{"direct app: name blocked", "direct app: address blocked", "direct app: name unresolved", "fake DNS record missing"} {
		tun2socksLog.Warnf("[TCP] dial %s: %s", "198.18.0.7:443", refusal)
	}
	tun2socksLog.Warnf("[UDP] dial %s: %v", "[fd00::7]:443", errProcessBlocked)
	tun2socksLog.Warnf("[UDP] symmetric NAT %s->%s: drop packet from %s", "198.18.0.1:40000", "203.0.113.9:3478", "203.0.113.10:3478")

	for _, line := range logs() {
		for _, secret := range []string{"198.18", "fd00", "203.0.113", "blocked-address.test"} {
			if strings.Contains(line.Message, secret) {
				t.Errorf("the log carries %q: %s", secret, line.Message)
			}
		}
	}
	if got := logs(); len(got) != 7 || got[0].Message != "[TCP] dial <addr>: process split: blocked" || got[6].Message != "[UDP] symmetric NAT <addr>-><addr>: drop packet from <addr>" {
		t.Fatalf("lines = %+v", got)
	}
}
