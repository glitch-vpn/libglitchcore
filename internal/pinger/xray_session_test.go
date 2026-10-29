//go:build !no_xray

package pinger

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"google.golang.org/protobuf/proto"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
	"github.com/glitch-vpn/libglitchcore/internal/xraydialer"
)

// A ping during a session leaves the session's direct dials by name resolving
// through the session's own DNS: a domain direct entry and a geoip one.
func TestPingKeepsTheSessionsDirectDials(t *testing.T) {
	geo, err := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{
		{Code: "LOOPBACK-TEST", Cidr: []*geodata.CIDR{{Ip: net.ParseIP("127.0.0.2").To4(), Prefix: 32}}},
		{Code: "CN", Cidr: []*geodata.CIDR{{Ip: net.ParseIP("203.0.113.0").To4(), Prefix: 24}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	geoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(geoDir, "geoip.dat"), geo, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("xray.location.asset", geoDir)

	listener, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("listen on 127.0.0.2: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var hits atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port

	prof := routing.Profile{
		Mode:           routing.ModeProxyAll,
		Tiers:          []routing.Tier{{Direct: []string{"domain:named.test", "geoip:loopback-test"}}},
		DomainStrategy: "IPOnDemand",
	}
	res, err := xrayconfig.BuildConfig([]string{"vless://11111111-1111-1111-1111-111111111111@127.0.0.1:1?type=tcp&security=none#t"}, xrayconfig.BalancerOptions{}, prof, "none")
	if err != nil {
		t.Fatal(err)
	}
	xrayconfig.ApplyDNS(res.Config, dnsconfig.Config{
		Mode:    dnsconfig.ModeFakeIP,
		Servers: []string{"127.0.0.1:1"},
		Hosts:   map[string][]string{"named.test": {"127.0.0.2"}, "geo.test": {"127.0.0.2"}},
	}, prof)
	built, err := res.Config.Build()
	if err != nil {
		t.Fatal(err)
	}
	inst, err := xraydialer.NewSession(context.Background(), built)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		xraydialer.EndSession(inst)
		_ = inst.Close()
	})
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = measureXray(ctx, "vless://11111111-1111-1111-1111-111111111111@127.0.0.1:1?type=tcp&security=none#ping", "http://127.0.0.1:1/")

	for _, name := range []string{"named.test", "geo.test"} {
		before := hits.Load()
		dialSession(t, inst, name, port)
		if hits.Load() == before {
			t.Errorf("%s did not reach its address directly after a ping", name)
		}
	}
}

func dialSession(t *testing.T, inst *xrayCore.Instance, name string, port int) {
	t.Helper()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: xrayconfig.AppTrafficTag})
	conn, err := xrayCore.Dial(ctx, inst, xnet.TCPDestination(xnet.ParseAddress(name), xnet.Port(port)))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("x"))
	ended := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		close(ended)
	}()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Errorf("the flow to %s did not end", net.JoinHostPort(name, strconv.Itoa(port)))
	}
	_ = conn.Close()
	<-ended
}
