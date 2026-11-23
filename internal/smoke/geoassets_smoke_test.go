//go:build integration

package smoke

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"
)

// writeGeoFixtures materializes minimal geosite.dat/geoip.dat (v2fly wire
// format, shared by xray and mihomo) carrying a GLITCH-TEST list. A CN list
// rides along because mihomo verifies geo files by loading "CN" and replaces
// a file that lacks it with a downloaded one.
func writeGeoFixtures(t *testing.T, dir string) {
	t.Helper()
	site, err := proto.Marshal(&geoSiteList{Entry: []*geoSite{
		siteWithCode("GLITCH-TEST",
			&geoDomain{Type: geoRootDomain, Value: "glitch.test"},
			&geoDomain{Type: geoFullDomain, Value: "exact.glitch.test"},
		),
		siteWithCode("CN", &geoDomain{Type: geoRootDomain, Value: "cn.glitch.test"}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geosite.dat"), site, 0o644); err != nil {
		t.Fatal(err)
	}
	ip, err := proto.Marshal(&geoIPList{Entry: []*geoIP{
		ipWithCode("GLITCH-TEST", &geoCIDR{Ip: net.ParseIP("198.51.100.0").To4(), Prefix: 24}),
		ipWithCode("CN", &geoCIDR{Ip: net.ParseIP("203.0.113.0").To4(), Prefix: 24}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat"), ip, 0o644); err != nil {
		t.Fatal(err)
	}
}
