//go:build !no_mihomo && (!no_xray || !no_awg)

package core

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/metacubex/mihomo/hub/executor"
)

// mihomo keeps cache.db open inside its home dir, so the dir outlives the test.
func mihomoTestHome(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "glitch-mihomo-listener-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureMihomoHome(dir); err != nil {
		t.Fatal(err)
	}
}

// A unit test, not smoke: the bridge listeners exist only behind a TUN device.
func TestMihomoBridgeListeners_RefuseAnonymousClient(t *testing.T) {
	mihomoTestHome(t)
	x := &CoreController{}
	dns := dnsconfig.Config{}
	prof := routing.Profile{Mode: routing.ModeDirectAll, Tiers: []routing.Tier{{Proxy: []string{"process:app.exe"}}}}
	in, b, err := x.mihomoBuildBridgeInbound(&dns, prof)
	if err != nil {
		t.Fatalf("mihomoBuildBridgeInbound: %v", err)
	}
	cfg, err := mihomoconfig.BuildConfig([]string{loopbackTestVlessLink}, in, mihomoconfig.Options{}, prof)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	executor.ApplyConfig(cfg, true)
	t.Cleanup(mihomoTeardown)

	mixed := fmt.Sprintf("127.0.0.1:%d", b.mixedPort)
	forceProxy := fmt.Sprintf("127.0.0.1:%d", in.ForceProxyPort)
	for _, addr := range []string{mixed, forceProxy} {
		requireSocksRefusesAnonymous(t, addr)
		requireSocks4RefusesAnonymous(t, addr)
		requireHTTPConnectRefusesAnonymous(t, addr)
	}
	requireSocksAcceptsURL(t, b.proxyURL)
	requireSocksAcceptsURL(t, b.forceProxyURL)
}

func TestMihomoTunnelDial_RefusesAfterItsSessionEnds(t *testing.T) {
	x := &CoreController{}
	dial := x.mihomoTunnelDial("")
	x.clearSessionState()
	if conn, err := dial(context.Background(), "tcp", "example.com:443"); err == nil {
		_ = conn.Close()
		t.Fatal("a dial from an ended session must not reach mihomo's tunnel")
	}
}
