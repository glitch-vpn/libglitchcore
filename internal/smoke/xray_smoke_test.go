//go:build integration && !no_xray

package smoke

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/xtls/xray-core/common/geodata"
	xrayCore "github.com/xtls/xray-core/core"
)

func startVlessServerTo(t *testing.T, decryption, redirect string) int {
	t.Helper()
	if decryption == "" {
		decryption = "none"
	}
	port := freePort(t)
	cfg := fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": %d,
			"protocol": "vless",
			"settings": {"clients": [{"id": %q}], "decryption": %q}
		}],
		"outbounds": [{"protocol": "freedom", "settings": {"redirect": %q, "finalRules": [{"action": "allow"}]}}]
	}`, port, testUUID, decryption, redirect)
	inst, err := xrayCore.StartInstance("json", []byte(cfg))
	if err != nil {
		t.Fatalf("vless server: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return port
}

// startVMessServer runs xray's VMess inbound on loopback, over plain TCP or
// over WebSocket at /vm.
func startVMessServer(t *testing.T, wsPath string) int {
	t.Helper()
	port := freePort(t)
	stream := `{"network": "tcp"}`
	if wsPath != "" {
		stream = fmt.Sprintf(`{"network": "ws", "wsSettings": {"path": %q}}`, wsPath)
	}
	cfg := fmt.Sprintf(`{
		"log": {"loglevel": "warning"},
		"inbounds": [{
			"listen": "127.0.0.1",
			"port": %d,
			"protocol": "vmess",
			"settings": {"clients": [{"id": %q}]},
			"streamSettings": %s
		}],
		"outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
	}`, port, testUUID, stream)
	inst, err := xrayCore.StartInstance("json", []byte(cfg))
	if err != nil {
		t.Fatalf("vmess server: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return port
}

type (
	geoSiteList = geodata.GeoSiteList
	geoIPList   = geodata.GeoIPList
	geoDomain   = geodata.Domain
	geoSite     = geodata.GeoSite
	geoIP       = geodata.GeoIP
	geoCIDR     = geodata.CIDR
)

const (
	geoRootDomain = geodata.Domain_Domain
	geoFullDomain = geodata.Domain_Full
)

func siteWithCode(code string, domains ...*geoDomain) *geoSite {
	return &geoSite{Code: code, Domain: domains}
}

func ipWithCode(code string, network *geoCIDR) *geoIP {
	return &geoIP{Code: code, Cidr: []*geoCIDR{network}}
}

func startProxyEngine(t *testing.T, links string, extraOpts map[string]string) {
	t.Helper()
	startProxyEngineDNS(t, links, extraOpts, nil)
}

// startProxyEngineDNS returns the loopback SOCKS port so a test can drive
// traffic through the engine it just started.
func startProxyEngineDNS(t *testing.T, links string, extraOpts map[string]string, dns *dnsconfig.Config) int {
	t.Helper()
	return startEngineInProxyMode(t, "xray", links, extraOpts, dns)
}

// SOCKS inbound -> vless client -> in-process vless server -> freedom ->
// loopback echo; the IPEvent can only carry the echo body via that path.
func TestSmoke_ProxyMode_ServerAndIPEvents(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upstream := startVlessServer(t)
	echoV4 := echoBody(t, "198.51.100.42")
	echoV6 := echoBody(t, "2001:db8::42")

	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Smoke%%20A", testUUID, upstream)
	startProxyEngine(t, link, map[string]string{
		"probeUrl":    echoV4.URL,
		"ipv4EchoUrl": echoV4.URL,
		"ipv6EchoUrl": echoV6.URL,
	})

	ev.waitFor(t, core.EngineConnected, 30*time.Second)

	var sel struct {
		Engine   string `json:"engine"`
		Strategy string `json:"strategy"`
		Total    int    `json:"total"`
		Selected *struct {
			Index    int    `json:"index"`
			Name     string `json:"name"`
			Host     string `json:"host"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"selected"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.ServerEvent, 15*time.Second)), &sel); err != nil {
		t.Fatalf("ServerEvent JSON: %v", err)
	}
	if sel.Engine != "xray" || sel.Total != 1 || sel.Strategy != "" {
		t.Fatalf("selection = %+v", sel)
	}
	if sel.Selected == nil || sel.Selected.Host != "127.0.0.1" || sel.Selected.Port != upstream ||
		sel.Selected.Name != "Smoke A" || sel.Selected.Protocol != "vless" {
		t.Fatalf("selected = %+v", sel.Selected)
	}

	// First liveness probe (and the fetch behind it) fires after the 5s quick
	// interval.
	var ip struct {
		IPv4      string `json:"ipv4"`
		IPv6      string `json:"ipv6"`
		IPv4Error string `json:"ipv4Error"`
		IPv6Error string `json:"ipv6Error"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.IPEvent, 30*time.Second)), &ip); err != nil {
		t.Fatalf("IPEvent JSON: %v", err)
	}
	if ip.IPv4 != "198.51.100.42" {
		t.Fatalf("ipv4 = %q (err %q)", ip.IPv4, ip.IPv4Error)
	}
	if ip.IPv6 != "2001:db8::42" {
		t.Fatalf("ipv6 = %q (err %q)", ip.IPv6, ip.IPv6Error)
	}
}

// A fresh status sink (new isolate after hot restart / app relaunch) must get
// the live session's view replayed without calling connect().
func TestSmoke_ReplayOnAttach(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upstream := startVlessServer(t)
	echo := echoBody(t, "198.51.100.44")
	link := fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none&type=tcp#Replay", testUUID, upstream)
	startProxyEngine(t, link, map[string]string{
		"probeUrl":    echo.URL,
		"ipv4EchoUrl": echo.URL,
		"disableIPv6": "1",
	})
	ev.waitFor(t, core.EngineConnected, 30*time.Second)
	ev.waitFor(t, core.ServerEvent, 15*time.Second)
	ev.waitFor(t, core.IPEvent, 30*time.Second)

	fresh := captureEvents(t) // registering the sink triggers the replay
	fresh.waitFor(t, core.EngineConnected, 10*time.Second)
	if sel := fresh.waitFor(t, core.ServerEvent, 10*time.Second); !strings.Contains(sel, `"name":"Replay"`) {
		t.Fatalf("replayed selection = %s", sel)
	}
	if ip := fresh.waitFor(t, core.IPEvent, 10*time.Second); !strings.Contains(ip, "198.51.100.44") {
		t.Fatalf("replayed ip = %s", ip)
	}
	fresh.waitFor(t, core.StatsEvent, 10*time.Second)
}

func TestSmoke_Balancer_ServerEventPool(t *testing.T) {
	core.Initialize()
	ev := captureEvents(t)

	upA := startVlessServer(t)
	upB := startVlessServer(t)
	echo := echoBody(t, "198.51.100.43")

	links := fmt.Sprintf(
		"vless://%s@127.0.0.1:%d?security=none&type=tcp#Pool%%20A\nvless://%s@127.0.0.1:%d?security=none&type=tcp#Pool%%20B",
		testUUID, upA, testUUID, upB,
	)
	startProxyEngine(t, links, map[string]string{
		"balancerStrategy": "leastping",
		"probeUrl":         echo.URL,
		"ipv4EchoUrl":      echo.URL,
		"disableIPv6":      "1",
	})

	ev.waitFor(t, core.EngineConnected, 30*time.Second)

	var sel struct {
		Strategy string `json:"strategy"`
		Total    int    `json:"total"`
		Selected *struct {
			Index int    `json:"index"`
			Name  string `json:"name"`
		} `json:"selected"`
		Servers []struct {
			Index int    `json:"index"`
			Name  string `json:"name"`
			Port  int    `json:"port"`
		} `json:"servers"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.ServerEvent, 15*time.Second)), &sel); err != nil {
		t.Fatalf("ServerEvent JSON: %v", err)
	}
	if sel.Strategy != "leastping" || sel.Total != 2 || len(sel.Servers) != 2 {
		t.Fatalf("selection = %+v", sel)
	}
	if sel.Servers[0].Name != "Pool A" || sel.Servers[1].Name != "Pool B" ||
		sel.Servers[0].Port != upA || sel.Servers[1].Port != upB {
		t.Fatalf("pool = %+v", sel.Servers)
	}
	// No server is named until traffic identifies the outbound in use.
	if sel.Selected != nil {
		t.Fatalf("selected = %+v before any traffic identified a server", sel.Selected)
	}

	var ip struct {
		IPv4      string `json:"ipv4"`
		IPv6Error string `json:"ipv6Error"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.IPEvent, 30*time.Second)), &ip); err != nil {
		t.Fatalf("IPEvent JSON: %v", err)
	}
	if ip.IPv4 != "198.51.100.43" {
		t.Fatalf("ipv4 = %q", ip.IPv4)
	}
	if ip.IPv6Error != "disabled" {
		t.Fatalf("ipv6Error = %q, want disabled", ip.IPv6Error)
	}
}
