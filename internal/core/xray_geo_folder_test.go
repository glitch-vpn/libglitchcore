//go:build !no_xray

package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/geodata"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"
	xrouting "github.com/xtls/xray-core/features/routing"
	rsession "github.com/xtls/xray-core/features/routing/session"

	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
)

func writeGeoIPFolder(t *testing.T, code string, cidr *geodata.CIDR) string {
	t.Helper()
	raw, err := proto.Marshal(&geodata.GeoIPList{Entry: []*geodata.GeoIP{{Code: code, Cidr: []*geodata.CIDR{cidr}}}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// routeInXraySession runs the start path's geo steps over dir, builds xray's
// router from a `direct geoip:XX` rule and returns the tag chosen for ip; the
// rule's own direct outbound is tagged "direct-0".
func routeInXraySession(t *testing.T, dir, ip string) string {
	t.Helper()
	applyGeoAssetsDir(dir)
	if err := dropXrayGeoMatchersOnFolderChange(); err != nil {
		t.Fatal(err)
	}
	prof, err := routingFromOpts(map[string]string{"routingTiers": `[{"direct":["geoip:xx"]}]`})
	if err != nil {
		t.Fatal(err)
	}
	res, err := xrayconfig.BuildConfig([]string{bridgeTestVlessLink}, xrayconfig.BalancerOptions{}, prof, "none")
	if err != nil {
		t.Fatal(err)
	}
	built, err := res.Config.Build()
	if err != nil {
		t.Fatal(err)
	}
	inst, err := xrayCore.New(built)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()
	router := inst.GetFeature(xrouting.RouterType()).(xrouting.Router)
	dest := xnet.TCPDestination(xnet.ParseAddress(ip), 443)
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: dest}})
	ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: xrayconfig.AppTrafficTag})
	route, err := router.PickRoute(rsession.AsRoutingContext(ctx))
	if err != nil {
		return "(catch-all)"
	}
	return route.GetOutboundTag()
}

func TestXrayGeoFolderChange_NextSessionReadsItsOwnFile(t *testing.T) {
	t.Setenv(xrayAsset, "")
	xrayGeoFolder = ""
	t.Cleanup(func() { applyGeoAssetsDir(""); xrayGeoFolder = "" })

	first := writeGeoIPFolder(t, "XX", &geodata.CIDR{Ip: []byte{5, 0, 0, 0}, Prefix: 8})
	second := writeGeoIPFolder(t, "XX", &geodata.CIDR{Ip: []byte{7, 0, 0, 0}, Prefix: 8})

	if got := routeInXraySession(t, first, "5.1.1.1"); got != "direct-0" {
		t.Fatalf("first folder, 5.1.1.1 routed %q, want direct-0", got)
	}
	// No collection between the sessions: the first session's matcher is
	// still reachable from the cache unless the start path drops it.
	if got := routeInXraySession(t, second, "5.1.1.1"); got == "direct-0" {
		t.Fatalf("second folder still matches the first folder's list for 5.1.1.1")
	}
	if got := routeInXraySession(t, second, "7.1.1.1"); got != "direct-0" {
		t.Fatalf("second folder, 7.1.1.1 routed %q, want direct-0", got)
	}
}

func TestXrayGeoFolderChange_NewFolderWithoutOldCodeStarts(t *testing.T) {
	t.Setenv(xrayAsset, "")
	xrayGeoFolder = ""
	t.Cleanup(func() { applyGeoAssetsDir(""); xrayGeoFolder = "" })

	first := writeGeoIPFolder(t, "XX", &geodata.CIDR{Ip: []byte{5, 0, 0, 0}, Prefix: 8})
	second := writeGeoIPFolder(t, "YY", &geodata.CIDR{Ip: []byte{7, 0, 0, 0}, Prefix: 8})
	routeInXraySession(t, first, "5.1.1.1")
	applyGeoAssetsDir(second)
	if err := dropXrayGeoMatchersOnFolderChange(); err != nil {
		t.Fatalf("a folder without the earlier session's code: %v", err)
	}
}
