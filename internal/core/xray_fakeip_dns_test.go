//go:build !no_mihomo && !no_xray

package core

import (
	"context"
	"net"
	"strconv"
	"testing"

	D "github.com/miekg/dns"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// xrayFakeIPSession runs xray with fake-ip on: the general resolver sits
// behind a socks recorder standing in for the proxy, at an address off the
// local networks, since a resolver on them is reached direct on purpose; the
// recorder reports the address without connecting, so nothing listens there.
// The direct resolver listens on loopback and reports what reached it. The
// app reaches the instance through the TUN layer's entry. The direct resolver
// answers vk.ru with its own address and port, so a direct dial it resolved
// completes against it: xray's dialer is one per process, and a dial left
// retrying its lookup after the instance closes would resolve through the
// next test's instance.
func xrayFakeIPSession(t *testing.T, prof routing.Profile, filter []string) (app xrayEntry, proxied, fromDevice chan string, directPort int) {
	t.Helper()
	directPort, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	fromDevice = make(chan string, 8)
	listenDirect(t, net.IPv4(127, 0, 0, 2), directPort, fromDevice, answerOverTCP(map[string][]net.IP{"vk.ru": {net.IPv4(127, 0, 0, 2)}}))
	proxied = make(chan string, 8)
	socksPort := socksRecorder(t, proxied)

	dns := dnsconfig.Config{
		Mode:          dnsconfig.ModeFakeIP,
		Servers:       []string{"tcp://" + generalResolver + ":53"},
		DirectServers: []string{"tcp://127.0.0.2:" + strconv.Itoa(directPort)},
		FakeIPFilter:  filter,
	}
	inst := startSniffInstanceDNS(t, prof, socksPort, dns)
	x := &CoreController{}
	return xrayAppEntry(t, x, inst), proxied, fromDevice, directPort
}

// generalResolver is the general resolver's address: off the local networks.
const generalResolver = "9.9.9.9"

func sendQuery(t *testing.T, app xrayEntry, name string, qtype uint16) {
	t.Helper()
	resolver := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
	pc, err := app.DialUDP(addrPortOf(resolver))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	q := new(D.Msg)
	q.SetQuestion(name+".", qtype)
	query, _ := q.Pack()
	if _, err := pc.WriteTo(query, resolver); err != nil {
		t.Fatal(err)
	}
}

// dialFakeIP asks fakedns for the name and dials the fake address: what xray
// looks up to carry the flow is the lookup under test.
func dialFakeIP(t *testing.T, app xrayEntry, name string, port int) {
	t.Helper()
	ip := fakeAnswer(t, app, name, D.TypeA)
	if ip == nil {
		t.Fatalf("no fake answer for %s", name)
	}
	conn, err := app.DialTCP(context.Background(), addrPortOf(&net.TCPAddr{IP: ip, Port: port}))
	if err != nil {
		t.Fatalf("dial %s: %v", name, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
}

// With fake-ip on, a name the filter keeps off the pool is resolved through
// the proxy; a direct tier's name is resolved by the direct resolver, direct,
// when freedom dials it; and under a resolving strategy the router's lookup
// of an unlisted name goes through the proxy, never from the device.
func TestXray_FakeIPLookupsTravelWithTheirFlows(t *testing.T) {
	direct := routing.Profile{Mode: routing.ModeProxyAll, Tiers: []routing.Tier{{Direct: []string{"domain:ru"}}}}

	app, proxied, fromDevice, _ := xrayFakeIPSession(t, direct, []string{"full:outside.test"})
	sendQuery(t, app, "outside.test", D.TypeA)
	requireQueryTravels(t, proxied, fromDevice, "proxy:"+generalResolver)

	app, proxied, fromDevice, directPort := xrayFakeIPSession(t, direct, nil)
	dialFakeIP(t, app, "vk.ru", directPort)
	requireQueryTravels(t, proxied, fromDevice, "direct:127.0.0.2")

	resolving := routing.Profile{Mode: routing.ModeProxyAll, DomainStrategy: "IPIfNonMatch", Tiers: []routing.Tier{{Direct: []string{"domain:ru"}, Block: []string{"192.0.2.0/24"}}}}
	app, proxied, fromDevice, _ = xrayFakeIPSession(t, resolving, nil)
	dialFakeIP(t, app, "lookup.test", 443)
	requireQueryTravels(t, proxied, fromDevice, "proxy:"+generalResolver)
}
