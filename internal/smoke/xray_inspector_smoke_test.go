//go:build integration && !no_xray

package smoke

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
)

// The inspector reads xray's access records, which must flow with logging off
// whatever logLevel the start carries.
func TestSmoke_XrayInspectorReportsConnectionsWithLoggingOff(t *testing.T) {
	core.Initialize()
	core.ApplyStatusVerbosity(-1)
	ev := captureEvents(t)
	core.ApplyConnInspector(true)
	t.Cleanup(func() { core.ApplyConnInspector(false) })

	upstream := startVlessServer(t)
	echo := echoBody(t, "198.51.100.49")
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Inspect", testUUID, upstream)
	proxyPort := startEngineInProxyMode(t, "xray", link, map[string]string{
		"probeUrl":          echo.URL,
		"resolveExternalIp": "0",
		"disableIPv6":       "1",
	}, nil)
	ev.waitFor(t, core.EngineConnected, 30*time.Second)

	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hold.Close() })
	go func() {
		for {
			c, err := hold.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	holdPort := uint16(hold.Addr().(*net.TCPAddr).Port)
	go func() { _, _ = socksConnect(proxyPort, "127.0.0.1", holdPort) }()
	if _, ok := ev.waitForConn(t, func(r connRecord) bool { return r.Engine == "xray" }, 10*time.Second); !ok {
		t.Fatalf("no xray ConnEvent with logging off; captured %v", ev.all(core.ConnEvent))
	}
}
