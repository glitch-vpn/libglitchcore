//go:build !no_xray

package core

import (
	"context"
	"net/url"
	"testing"

	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
	xrayCore "github.com/xtls/xray-core/core"
)

func startXrayForTest(t *testing.T, build func(res *xrayconfig.BuildResult)) {
	t.Helper()
	res, err := xrayconfig.BuildConfig([]string{loopbackTestVlessLink}, xrayconfig.BalancerOptions{}, routing.Profile{}, "none")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	build(res)
	built, err := res.Config.Build()
	if err != nil {
		t.Fatalf("cfg.Build: %v", err)
	}
	inst, err := xrayCore.New(built)
	if err != nil {
		t.Fatalf("xray New: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("xray Start: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close() })
}

// The TUN path's two inbounds: the one tun2socks feeds and the force-proxy one.
// A unit test, not smoke: proxy mode opens neither, and TUN mode needs a device.
func TestXrayLoopbackInbounds_RefuseAnonymousClient(t *testing.T) {
	var bridgeURL, forceProxyURL string
	startXrayForTest(t, func(res *xrayconfig.BuildResult) {
		_, u, err := xrayconfig.ApplyLocalSocksInbound(res.Config)
		if err != nil {
			t.Fatalf("ApplyLocalSocksInbound: %v", err)
		}
		bridgeURL = u
		if forceProxyURL, err = xrayconfig.ApplyForceProxyInbound(res.Config); err != nil {
			t.Fatalf("ApplyForceProxyInbound: %v", err)
		}
	})
	for _, socksURL := range []string{bridgeURL, forceProxyURL} {
		u, err := url.Parse(socksURL)
		if err != nil {
			t.Fatal(err)
		}
		requireSocksRefusesAnonymous(t, u.Host)
		requireSocks4RefusesAnonymous(t, u.Host)
		requireHTTPConnectRefusesAnonymous(t, u.Host)
		requireSocksAcceptsURL(t, socksURL)
	}
}

func TestXrayExitEchoDial_RefusesAfterItsSessionEnds(t *testing.T) {
	x := &CoreController{}
	dial := x.xrayExitEchoDial(nil)
	x.clearSessionState()
	if conn, err := dial(context.Background(), "tcp", "example.com:443"); err == nil {
		_ = conn.Close()
		t.Fatal("a dial from an ended session must not reach xray")
	}
}
