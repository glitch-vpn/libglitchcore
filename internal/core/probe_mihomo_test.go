//go:build !no_mihomo && !no_xray

package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/hub/executor"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// The probe's lookup, held to IPv4 until the exit's IPv6 carries, goes through
// the WireGuard outbound's own tunnel, as the outbound's lookups for its flows
// do. The peer is dead, so the lookup finds nothing, and the session's resolver
// is never asked from the device whatever the routing profile says.
func TestMihomoProbeDial_ALookupNeverLeavesFromTheDevice(t *testing.T) {
	skipWhereMihomoRaces(t)
	for _, c := range []struct {
		name    string
		profile routing.Profile
	}{
		{"proxy-all", routing.Profile{Mode: routing.ModeProxyAll}},
		{"direct-all", routing.Profile{Mode: routing.ModeDirectAll}},
		{"probe host direct", routing.Profile{Mode: routing.ModeProxyAll, Tiers: []routing.Tier{{Direct: []string{"domain:probe.test"}}}}},
	} {
		t.Run(c.name, func(t *testing.T) {
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
			links := []string{link}
			inbound := mihomoconfig.Inbound{Bridge: true, DNS: dnsconfig.Config{
				Mode: dnsconfig.ModeFakeIP, Servers: []string{resolverAddr}, DirectServers: []string{resolverAddr},
			}}
			cfg, err := mihomoconfig.BuildConfig(links, inbound, mihomoconfig.Options{}, c.profile)
			if err != nil {
				t.Fatalf("BuildConfig: %v", err)
			}
			executor.ApplyConfig(cfg, true)

			x := &CoreController{}
			x.exitIPv6.Store(exitIPv6Pending)
			dial := x.mihomoProbeDial(links, inbound, x.sessionGen.Load())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if conn, err := dial(ctx, "tcp", "probe.test:80"); err == nil {
				_ = conn.Close()
				t.Fatal("a dead peer carried the probe")
			}
			select {
			case q := <-asked:
				t.Fatalf("the resolver was asked %q from the device", q)
			case <-time.After(300 * time.Millisecond):
			}
		})
	}
}

// Only WireGuard and AmneziaWG find a name's address themselves; the rest send
// the name to their server, so the probe is not pinned for them.
func TestResolvesNamesLocally_OnlyWireGuardAndAmneziaWGLinksDo(t *testing.T) {
	if mihomoconfig.ResolvesNamesLocally([]string{vlessTestLink, "hysteria2://p@h.example:443"}) {
		t.Fatal("a pool of VLESS and Hysteria2 reads as resolving names locally")
	}
	if !mihomoconfig.ResolvesNamesLocally([]string{vlessTestLink, "awg://AAAA#one"}) {
		t.Fatal("a pool holding an AmneziaWG link reads as not resolving names locally")
	}
	if !mihomoconfig.ResolvesNamesLocally([]string{"wireguard://k@h:51820?publickey=p"}) {
		t.Fatal("a WireGuard link reads as not resolving names locally")
	}
}
