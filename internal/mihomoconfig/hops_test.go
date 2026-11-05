//go:build !no_xray

package mihomoconfig

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"

	D "github.com/miekg/dns"
	xrayCore "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// startFirstHop runs a shadowsocks server whose own connections leave from
// 127.0.0.3, so a listener can tell a query that came through it from one
// that came from the client.
func startFirstHop(t *testing.T) string {
	t.Helper()
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"shadowsocks","settings":{"method":"chacha20-ietf-poly1305","password":"pw","network":"tcp"}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]},"sendThrough":"127.0.0.3"}]}`, port)
	server, err := xrayCore.StartInstance("json", []byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return fmt.Sprintf("ss://chacha20-ietf-poly1305:pw@127.0.0.1:%d#first", port)
}

// startDNS answers every A query with answers[name] and records who asked.
func startDNS(t *testing.T, answers map[string]string) (addr string, askers func() []string) {
	t.Helper()
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	started := make(chan struct{})
	server := &D.Server{Listener: listener, NotifyStartedFunc: func() { close(started) }, Handler: D.HandlerFunc(func(w D.ResponseWriter, req *D.Msg) {
		mu.Lock()
		seen = append(seen, w.RemoteAddr().(*net.TCPAddr).IP.String())
		mu.Unlock()
		reply := new(D.Msg)
		reply.SetReply(req)
		q := req.Question[0]
		if ip, ok := answers[strings.TrimSuffix(q.Name, ".")]; ok && q.Qtype == D.TypeA {
			reply.Answer = append(reply.Answer, &D.A{Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP(ip).To4()})
		}
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	return fmt.Sprintf("127.0.0.1:%d", listener.Addr().(*net.TCPAddr).Port), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

func chainOf(entry string, later ...string) routing.Profile {
	servers := []routing.TargetServer{{ID: "a", Link: entry}}
	hops := []string{"a"}
	for i, link := range later {
		id := fmt.Sprintf("b%d", i)
		servers = append(servers, routing.TargetServer{ID: id, Link: link})
		hops = append(hops, id)
	}
	return routing.Profile{
		Tiers:   []routing.Tier{{Routes: []routing.Route{{To: "c1", Match: []string{"full:c.example"}}}}},
		Targets: &routing.Targets{Version: 1, Servers: servers, Chains: []routing.TargetChain{{ID: "c1", Hops: hops}}},
	}
}

const (
	udpHopByName = "hysteria2://pw@hop2.test:443?insecure=1#h"
	wgKeyA       = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	wgKeyB       = "ys6ln6BOSOotjcRKGYel/HW/HQ65w+bAg8ac9VVtLWo="
)

func twoPeerWireGuard(hostA, hostB string) string {
	return "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.10.0.51/32\n\n" +
		"[Peer]\nPublicKey = " + wgKeyA + "\nAllowedIPs = 10.0.0.0/24\nEndpoint = " + hostA + ":51820\n\n" +
		"[Peer]\nPublicKey = " + wgKeyB + "\nAllowedIPs = 10.0.1.0/24\nEndpoint = " + hostB + ":51821\n"
}

// A UDP hop after the first is looked up by mihomo's own resolver unless the
// core does it first, so the core asks a DNS server through the hop before it
// and builds the hop with the answer, keeping the name for TLS.
func TestNamedTargets_UDPLaterHopIsResolvedThroughTheHopBefore(t *testing.T) {
	dnsAddr, askers := startDNS(t, map[string]string{"hop2.test": "192.0.2.40", "peera.test": "192.0.2.41", "peerb.test": "192.0.2.42"})
	first := startFirstHop(t)
	opts := Options{HopResolver: dnsAddr}

	raw, _, err := buildRaw([]string{namedPoolLink}, Inbound{MixedPort: 7890}, opts, chainOf(first, udpHopByName))
	if err != nil {
		t.Fatal(err)
	}
	hop := proxyNamed(t, raw.Proxy, "rc-c1-1")
	if hop["server"] != "192.0.2.40" || hop["sni"] != "hop2.test" {
		t.Errorf("later hop = server %v, sni %v; want the answer and the original name", hop["server"], hop["sni"])
	}
	if got := askers(); len(got) == 0 || slices.ContainsFunc(got, func(a string) bool { return a != "127.0.0.3" }) {
		t.Errorf("the lookup came from %v, want only from the first hop (127.0.0.3)", got)
	}

	raw, _, err = buildRaw([]string{namedPoolLink}, Inbound{MixedPort: 7890}, opts, chainOf(first, twoPeerWireGuard("peera.test", "peerb.test")))
	if err != nil {
		t.Fatal(err)
	}
	wg := proxyNamed(t, raw.Proxy, "rc-c1-1")
	peers := wg["peers"].([]map[string]any)
	if len(peers) != 2 || peers[0]["server"] != "192.0.2.41" || peers[1]["server"] != "192.0.2.42" || (wg["server"] != "192.0.2.41" && wg["server"] != "192.0.2.42") {
		t.Errorf("wireguard later hop = %v / %v: every peer endpoint is resolved through the hop before", wg["server"], peers)
	}
}

func TestNamedTargets_UDPLaterHopLookupFailureRefusesTheStart(t *testing.T) {
	dnsAddr, _ := startDNS(t, nil)
	first := startFirstHop(t)
	if _, _, err := buildRaw([]string{namedPoolLink}, Inbound{MixedPort: 7890}, Options{HopResolver: dnsAddr}, chainOf(first, udpHopByName)); err == nil {
		t.Error("a name nobody answers must refuse the start")
	}
	if _, _, err := buildRaw([]string{namedPoolLink}, Inbound{MixedPort: 7890}, Options{HopResolver: "127.0.0.1:1"}, chainOf(first, twoPeerWireGuard("192.0.2.50", "peerb.test"))); err == nil {
		t.Error("an unreachable resolver must refuse the start, a second peer's name included")
	}
}

// An address needs no lookup, and the first hop, which the client dials
// itself, and a TCP hop, whose name the hop before resolves, are left alone.
func TestNamedTargets_HopsThatNeedNoLookupAreNotResolved(t *testing.T) {
	opts := Options{HopResolver: "127.0.0.1:1"}
	for name, prof := range map[string]routing.Profile{
		"a UDP later hop by address": chainOf(namedLinkOne, "hysteria2://pw@192.0.2.31:443?insecure=1#h"),
		"a UDP first hop by name":    chainOf(udpHopByName, namedLinkOne),
		"a TCP later hop by name":    chainOf(namedLinkThr, namedLinkOne),
	} {
		raw, _, err := buildRaw([]string{namedPoolLink}, Inbound{MixedPort: 7890}, opts, prof)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if name == "a TCP later hop by name" && proxyNamed(t, raw.Proxy, "rc-c1-1")["server"] != "one.example" {
			t.Errorf("%s: the name must reach the hop before unchanged", name)
		}
	}
}

// ech=1 makes mihomo look the name up with its own resolver; a config list
// carries no lookup.
func TestNamedTargets_LaterHopEchLookupIsRefused(t *testing.T) {
	const base = "trojan://pw@192.0.2.60:443?sni=h.example"
	if _, _, err := buildRaw([]string{namedPoolLink}, Inbound{MixedPort: 7890}, Options{}, chainOf(namedLinkOne, base+"&ech=1#t")); err == nil {
		t.Error("a later hop that looks up its ECH config must be refused")
	}
	if _, _, err := buildRaw([]string{namedPoolLink}, Inbound{MixedPort: 7890}, Options{}, chainOf(base+"&ech=1#t", namedLinkOne)); err != nil {
		t.Errorf("the first hop is dialled by the client: %v", err)
	}
	if _, _, err := buildRaw([]string{namedPoolLink}, Inbound{MixedPort: 7890}, Options{}, chainOf(namedLinkOne, base+"&ech=AEX%2BDQBBAAAgACA=#t")); err != nil {
		t.Errorf("a config list needs no lookup: %v", err)
	}
}
