//go:build integration && no_xray && !no_mihomo

package smoke

import (
	"testing"

	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/metacubex/mihomo/listener/inbound"
)

func startVlessServerTo(t *testing.T, decryption, redirect string) int {
	t.Helper()
	port := freePort(t)
	in, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:    inboundOn("vless-smoke", port),
		Users:         []inbound.VlessUser{{UUID: testUUID}},
		Decryption:    decryption,
		AllowInsecure: decryption == "",
	})
	if err != nil {
		t.Fatalf("vless server: %v", err)
	}
	listenInboundTo(t, in, redirect)
	return port
}

func startVMessServer(t *testing.T, wsPath string) int {
	t.Helper()
	port := freePort(t)
	in, err := inbound.NewVmess(&inbound.VmessOption{
		BaseOption: inboundOn("vmess-smoke", port),
		Users:      []inbound.VmessUser{{UUID: testUUID}},
		WsPath:     wsPath,
	})
	if err != nil {
		t.Fatalf("vmess server: %v", err)
	}
	listenInbound(t, in)
	return port
}

type (
	geoSiteList = router.GeoSiteList
	geoIPList   = router.GeoIPList
	geoDomain   = router.Domain
	geoSite     = router.GeoSite
	geoIP       = router.GeoIP
	geoCIDR     = router.CIDR
)

const (
	geoRootDomain = router.Domain_Domain
	geoFullDomain = router.Domain_Full
)

func siteWithCode(code string, domains ...*geoDomain) *geoSite {
	return &geoSite{CountryCode: code, Domain: domains}
}

func ipWithCode(code string, network *geoCIDR) *geoIP {
	return &geoIP{CountryCode: code, Cidr: []*geoCIDR{network}}
}
