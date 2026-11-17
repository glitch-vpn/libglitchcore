//go:build !no_mihomo && !no_xray && with_tun2socks

package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	mihomoLog "github.com/metacubex/mihomo/log"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// A WireGuard outbound resolves the names of its flows inside its own tunnel:
// the session's resolver is never asked from the device's own address. The
// peer is dead, so the dial fails once the in-tunnel lookup gives up; the
// dial-error line shows the outbound carried the flow.
func TestMihomoWireGuard_ResolvesNamesInsideTheTunnel(t *testing.T) {
	skipWhereMihomoRaces(t)
	mihomoTestHome(t)
	t.Cleanup(mihomoTeardown)

	resolverAddr, asked := recordingResolver(t)
	deadPort, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	key := func(fill byte) string {
		return url.QueryEscape(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32)))
	}
	link := "wireguard://" + key(0x11) + "@127.0.0.1:" + strconv.Itoa(deadPort) + "?publickey=" + key(0x22) + "&address=10.66.0.2/32"

	dns := dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{resolverAddr}}
	cfg, err := mihomoconfig.BuildConfig([]string{link}, mihomoconfig.Inbound{Bridge: true, DNS: dns},
		mihomoconfig.Options{}, routing.Profile{Mode: routing.ModeProxyAll})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	executor.ApplyConfig(cfg, true)

	lines := mihomoLog.Subscribe()
	t.Cleanup(func() { mihomoLog.UnSubscribe(lines) })
	x := &CoreController{}
	app := &mihomoBridgeProxy{x: x, mark: x.sessionGen.Load()}

	const name = "inside.test"
	fake := fakeIPFor(t, name)
	conn, err := app.DialContext(context.Background(), bridgeTestFlow(M.TCP, &net.TCPAddr{IP: fake, Port: 443}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("x"))

	deadline := time.After(30 * time.Second)
	for {
		select {
		case q := <-asked:
			t.Fatalf("the resolver was asked %q from the device's own address", q)
		case ev := <-lines:
			if strings.Contains(ev.Payload, name+":443") && strings.Contains(ev.Payload, "error") {
				return
			}
		case <-deadline:
			t.Fatal("no dial-error line for the flow: the WireGuard outbound never carried it")
		}
	}
}
