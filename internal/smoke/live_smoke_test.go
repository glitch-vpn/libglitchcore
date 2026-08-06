//go:build integration

package smoke

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/core"
	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
)

// Links stay outside the repo - never commit them.
func readLiveLinks(t *testing.T) []string {
	t.Helper()
	path := os.Getenv("GLITCH_LIVE_LINKS_FILE")
	if path == "" {
		t.Skip("GLITCH_LIVE_LINKS_FILE not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("links file: %v", err)
	}
	var links []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			links = append(links, l)
		}
	}
	if len(links) == 0 {
		t.Fatal("links file is empty")
	}
	return links
}

// The loopback split test can only read xray's server-selection log, because
// on Windows the direct outbound binds the physical NIC and never reaches a
// 127.0.0.1 stub. Against a real exit the resolvers are reachable, so this one
// also proves the direct-routed name actually resolves and connects.
func TestLive_DirectServersResolveDirectNames(t *testing.T) {
	const (
		directResolver  = "77.88.8.8" // answers the direct-routed name
		generalResolver = "1.1.1.1"   // everything else
		directName      = "ya.ru"
	)
	links := readLiveLinks(t)
	core.Initialize()
	ev := captureEvents(t)
	core.ApplyStatusVerbosity(2)
	t.Cleanup(func() { core.ApplyStatusVerbosity(-1) })

	proxyPort := startProxyEngineDNS(t, strings.Join(links, "\n"), map[string]string{
		"directRules": "domain:" + directName,
		"disableIPv6": "1",
	}, &dnsconfig.Config{
		Mode:          dnsconfig.ModeFakeIP,
		Servers:       []string{generalResolver},
		DirectServers: []string{directResolver},
	})
	ev.waitFor(t, core.EngineConnected, 30*time.Second)

	if status, err := socksConnect(proxyPort, directName, 80); err != nil {
		t.Fatalf("direct-routed request (socks status %d): %v", status, err)
	}

	queriedVia := func(resolver string) func(string) bool {
		return func(msg string) bool {
			return strings.Contains(msg, "querying DNS for: "+directName) &&
				strings.Contains(msg, resolver)
		}
	}
	if ev.waitForLog(t, queriedVia(directResolver), 20*time.Second) == "" {
		t.Fatalf("%s was not resolved through the direct resolver %s", directName, directResolver)
	}
	// A fallback to the general resolver would mean the direct one never answered.
	if ev.waitForLog(t, queriedVia(generalResolver), time.Second) != "" {
		t.Fatalf("%s also went to the general resolver %s", directName, generalResolver)
	}
}

func TestLive_ServerAndIPEvents(t *testing.T) {
	links := readLiveLinks(t)
	core.Initialize()
	ev := captureEvents(t)

	startProxyEngine(t, strings.Join(links, "\n"), map[string]string{
		"balancerStrategy": "leastping",
	})

	ev.waitFor(t, core.EngineConnected, 30*time.Second)

	var sel struct {
		Total    int `json:"total"`
		Selected *struct {
			Host string `json:"host"`
		} `json:"selected"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.ServerEvent, 30*time.Second)), &sel); err != nil {
		t.Fatalf("ServerEvent JSON: %v", err)
	}
	if sel.Total != len(links) {
		t.Fatalf("total = %d, want %d", sel.Total, len(links))
	}
	if len(links) == 1 && (sel.Selected == nil || sel.Selected.Host == "") {
		t.Fatalf("selected = %+v", sel.Selected)
	}

	var ip struct {
		IPv4      string `json:"ipv4"`
		IPv4Error string `json:"ipv4Error"`
		IPv6      string `json:"ipv6"`
		IPv6Error string `json:"ipv6Error"`
	}
	if err := json.Unmarshal([]byte(ev.waitFor(t, core.IPEvent, 60*time.Second)), &ip); err != nil {
		t.Fatalf("IPEvent JSON: %v", err)
	}
	// v6 legitimately fails on v4-only exits; v4 must resolve.
	if ip.IPv4 == "" {
		t.Fatalf("no egress IPv4 (v4 err %q, v6 err %q)", ip.IPv4Error, ip.IPv6Error)
	}
	t.Logf("egress: v4=%s v6=%s", ip.IPv4, ip.IPv6)
}
