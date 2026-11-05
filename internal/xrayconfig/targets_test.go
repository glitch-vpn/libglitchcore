package xrayconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xrayCore "github.com/xtls/xray-core/core"
	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

const (
	poolLink  = "ss://chacha20-ietf-poly1305:pw@192.0.2.10:8388#pool"
	linkOne   = "ss://chacha20-ietf-poly1305:pw@one.example:8388#one"
	linkTwo   = "ss://chacha20-ietf-poly1305:pw@two.example:8388#two"
	linkThree = "vless://11111111-1111-1111-1111-111111111111@192.0.2.13:443?type=tcp&security=none#three"
)

func namedProfile(routes ...routing.Route) routing.Profile {
	return routing.Profile{
		Tiers: []routing.Tier{{Routes: routes}},
		Targets: &routing.Targets{
			Version: 1,
			Servers: []routing.TargetServer{{ID: "s1", Link: linkOne}, {ID: "s2", Link: linkTwo}, {ID: "s3", Link: linkThree}},
			Groups:  []routing.TargetGroup{{ID: "g1", Servers: []string{"s1", "s2"}}},
			Chains:  []routing.TargetChain{{ID: "c1", Hops: []string{"s1", "s2", "s3"}}},
		},
	}
}

func outboundByTag(t *testing.T, cfg *xrayConf.Config, tag string) xrayConf.OutboundDetourConfig {
	t.Helper()
	for _, ob := range cfg.OutboundConfigs {
		if ob.Tag == tag {
			return ob
		}
	}
	t.Fatalf("no outbound %q in %v", tag, tagsOf(cfg))
	return xrayConf.OutboundDetourConfig{}
}

func tagsOf(cfg *xrayConf.Config) []string {
	var out []string
	for _, ob := range cfg.OutboundConfigs {
		out = append(out, ob.Tag)
	}
	return out
}

func dialerProxyOf(ob xrayConf.OutboundDetourConfig) string {
	if ob.StreamSetting == nil || ob.StreamSetting.SocketSettings == nil {
		return ""
	}
	return ob.StreamSetting.SocketSettings.DialerProxy
}

func TestNamedTargets_TagsAndStructure(t *testing.T) {
	resolveAs(t, map[string]string{"one.example": "192.0.2.11", "two.example": "192.0.2.12"})
	prof := namedProfile(
		routing.Route{To: "s1", Match: []string{"full:a.example"}},
		routing.Route{To: "g1", Match: []string{"full:b.example"}},
		routing.Route{To: "c1", Match: []string{"full:c.example"}},
	)
	for _, links := range [][]string{{poolLink}, {poolLink, "ss://chacha20-ietf-poly1305:pw@192.0.2.14:8388#pool2"}} {
		res, err := BuildConfig(links, BalancerOptions{}, prof, "none")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := res.Config.Build(); err != nil {
			t.Fatalf("xray refused the config: %v", err)
		}
		cfg := res.Config
		for _, tag := range []string{"rt-s1", "rg-g1-0", "rg-g1-1", "rc-c1-0", "rc-c1-1", "rc-c1-2"} {
			outboundByTag(t, cfg, tag)
		}
		if got := tagsOf(cfg)[0]; got != "proxy" && got != "proxy-0" {
			t.Errorf("first outbound = %q: the pool must stay xray's default", got)
		}
		for i, want := range []string{"", "rc-c1-0", "rc-c1-1"} {
			if got := dialerProxyOf(outboundByTag(t, cfg, fmt.Sprintf("rc-c1-%d", i))); got != want {
				t.Errorf("hop %d dialerProxy = %q, want %q", i, got, want)
			}
		}
		if got := dialerProxyOf(outboundByTag(t, cfg, "rt-s1")); got != "" {
			t.Errorf("a named server dials directly, got dialerProxy %q", got)
		}
		var balancer *xrayConf.BalancingRule
		for _, b := range cfg.RouterConfig.Balancers {
			if b.Tag == "rb-g1" {
				balancer = b
			}
		}
		if balancer == nil || !slices.Equal(balancer.Selectors, xrayConf.StringList{"rg-g1-"}) || balancer.FallbackTag != "rg-g1-0" {
			t.Fatalf("group balancer = %+v", balancer)
		}
		if cfg.Observatory == nil || !slices.Contains(cfg.Observatory.SubjectSelector, "rg-g1-") {
			t.Fatalf("observatory must probe the group: %+v", cfg.Observatory)
		}
		raw, _ := json.Marshal(cfg.OutboundConfigs)
		if strings.Contains(string(raw), `"proxySettings":{`) {
			t.Error("a chain must use sockopt.dialerProxy, never proxySettings")
		}
		for _, tag := range res.OutboundTags {
			if strings.HasPrefix(tag, "rt-") || strings.HasPrefix(tag, "rg-") || strings.HasPrefix(tag, "rc-") {
				t.Errorf("named tag %q leaked into OutboundTags", tag)
			}
		}
		if len(res.Servers) != len(links) {
			t.Errorf("Servers = %v: named servers stay out of it", res.Servers)
		}
		for _, tag := range []string{"rt-s1", "rg-g1-0", "rg-g1-1", "rc-c1-0"} {
			if !slices.Contains(res.TrafficTags, tag) {
				t.Errorf("TrafficTags %v lack the directly dialled %q", res.TrafficTags, tag)
			}
		}
		for _, tag := range []string{"rc-c1-1", "rc-c1-2"} {
			if slices.Contains(res.TrafficTags, tag) {
				t.Errorf("TrafficTags %v count the later hop %q twice", res.TrafficTags, tag)
			}
		}
	}
}

func TestNamedTargets_OnlyWhatARouteNamesIsBuilt(t *testing.T) {
	resolveAs(t, nil)
	res, err := BuildConfig([]string{poolLink}, BalancerOptions{}, namedProfile(routing.Route{To: "s3", Match: []string{"full:a.example"}}), "none")
	if err != nil {
		t.Fatal(err)
	}
	if got := tagsOf(res.Config); !slices.Equal(got, []string{"proxy", "rt-s3"}) {
		t.Fatalf("outbounds = %v", got)
	}
}

func TestNamedTargets_RouteRulesFollowThePrecedence(t *testing.T) {
	resolveAs(t, map[string]string{"one.example": "192.0.2.11", "two.example": "192.0.2.12"})
	prof := namedProfile(
		routing.Route{To: "g1", Match: []string{"full:both.example", "full:all.example"}},
		routing.Route{To: "s1", Match: []string{"full:both.example", "full:one.example", "full:direct.example"}},
		routing.Route{To: "c1", Match: []string{"full:chain.example"}},
	)
	prof.Tiers[0].Block = []string{"full:blocked.example", "full:all.example"}
	prof.Tiers[0].Direct = []string{"full:direct.example", "full:all.example"}
	prof.Tiers[0].Proxy = []string{"full:proxied.example", "full:blocked.example", "full:both.example"}
	res, err := BuildConfig([]string{poolLink}, BalancerOptions{}, prof, "none")
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
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Close() })

	tcp, app := xnet.Network_TCP, AppTrafficTag
	pickRoutes(t, inst, []routedFlow{
		{"block beats proxy", app, tcp, "blocked.example", 443, blockTag},
		{"block beats direct and routes", app, tcp, "all.example", 443, blockTag},
		{"direct beats a route", app, tcp, "direct.example", 443, directTag},
		{"the first route wins, and beats proxy", app, tcp, "both.example", 443, "rg-g1-0"},
		{"a server route", app, tcp, "one.example", 443, "rt-s1"},
		{"a chain routes to its last hop", app, tcp, "chain.example", 443, "rc-c1-2"},
		{"proxy", app, tcp, "proxied.example", 443, OutboundTag},
		{"unmatched takes the catch-all", app, tcp, "other.example", 443, OutboundTag},
	})
}

func TestNamedTargets_LaterHopsAreNotResolved(t *testing.T) {
	resolveAs(t, map[string]string{"one.example": "192.0.2.11", "two.example": "192.0.2.12"})
	prof := namedProfile(routing.Route{To: "c1", Match: []string{"full:c.example"}})
	res, err := BuildConfig([]string{poolLink}, BalancerOptions{}, prof, "none")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(res.DialIPv4s, "192.0.2.11") {
		t.Errorf("DialIPv4s %v must pin the entry hop", res.DialIPv4s)
	}
	if slices.Contains(res.DialIPv4s, "192.0.2.12") {
		t.Errorf("DialIPv4s %v must not pin a later hop", res.DialIPv4s)
	}
	hop := outboundByTag(t, res.Config, "rc-c1-1")
	raw, _ := json.Marshal(hop)
	if !strings.Contains(string(raw), "two.example") || strings.Contains(string(raw), "192.0.2.12") {
		t.Errorf("a later hop keeps its host name for the hop before to resolve: %s", raw)
	}
	if got := hop.StreamSetting.SocketSettings.DomainStrategy; got != "" {
		t.Errorf("a later hop carries no domainStrategy, got %q", got)
	}
}

func TestNamedTargets_DirectlyDialledServersArePinned(t *testing.T) {
	resolveAs(t, map[string]string{"one.example": "192.0.2.11", "two.example": "192.0.2.12"})
	res, err := BuildConfig([]string{poolLink}, BalancerOptions{}, namedProfile(
		routing.Route{To: "s1", Match: []string{"full:a.example"}},
		routing.Route{To: "g1", Match: []string{"full:b.example"}},
	), "none")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		if !slices.Contains(res.DialIPv4s, ip) {
			t.Errorf("DialIPv4s %v lack %s", res.DialIPv4s, ip)
		}
	}
}

func TestNamedTargets_Refusals(t *testing.T) {
	resolveAs(t, nil)
	mutate := func(f func(*routing.Profile)) routing.Profile {
		p := namedProfile(routing.Route{To: "c1", Match: []string{"full:c.example"}})
		f(&p)
		return p
	}
	cases := map[string]routing.Profile{
		"a chain through a socks hop": mutate(func(p *routing.Profile) {
			p.Targets.Servers[1].Link = "socks5://user:pw@192.0.2.20:1080#proxy"
		}),
		"a chain through a hysteria2 hop": mutate(func(p *routing.Profile) {
			p.Targets.Servers[2].Link = "hysteria2://pw@192.0.2.21:443#h"
		}),
		"a server xray cannot build": mutate(func(p *routing.Profile) {
			p.Tiers[0].Routes[0].To = "s2"
			p.Targets.Servers[1].Link = "hysteria2://pw@192.0.2.21:443#h"
		}),
		"an undefined route target": mutate(func(p *routing.Profile) {
			p.Tiers[0].Routes[0].To = "nope"
		}),
	}
	for name, prof := range cases {
		if _, err := BuildConfig([]string{poolLink}, BalancerOptions{}, prof, "none"); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
	}
}

// startExitServer runs an xray shadowsocks server whose own connections to
// the world leave from source.
func startExitServer(t *testing.T, source string) (port int, stop func()) {
	t.Helper()
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"shadowsocks","settings":{"method":"chacha20-ietf-poly1305","password":"pw","network":"tcp"}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]},"sendThrough":%q}]}`, port, source)
	server, err := xrayCore.StartInstance("json", []byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return port, func() { _ = server.Close() }
}

// startRecordingForwarder relays to target and records who connected.
func startRecordingForwarder(t *testing.T, target string) (addr string, sources func() []string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var mu sync.Mutex
	var seen []string
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			seen = append(seen, c.RemoteAddr().(*net.TCPAddr).IP.String())
			mu.Unlock()
			go func() {
				defer c.Close()
				u, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer u.Close()
				go func() { _, _ = io.Copy(u, c) }()
				_, _ = io.Copy(c, u)
			}()
		}
	}()
	return l.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// startSourceEcho answers each connection with the address it came from.
func startSourceEcho(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(c, c.RemoteAddr().(*net.TCPAddr).IP.String())
			_ = c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func ssLoopback(port int, name string) string {
	return fmt.Sprintf("ss://chacha20-ietf-poly1305:pw@127.0.0.1:%d#%s", port, name)
}

// exitOf dials the address through the instance as app traffic and returns
// the source address the echo saw.
func exitOf(inst *xrayCore.Instance, address string, port int) (string, error) {
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: AppTrafficTag})
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := xrayCore.Dial(ctx, inst, xnet.TCPDestination(xnet.ParseAddress(address), xnet.Port(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(conn)
	if err == nil && len(b) == 0 {
		err = io.EOF
	}
	return string(b), err
}

// A named server exits from its own server, not the pool's; a chain's exit is
// dialled by hop 1 and never by the client; with hop 1 down the chain fails
// instead of leaving through the pool or direct.
func TestNamedTargets_LiveChainAndNamedServer(t *testing.T) {
	echoPort := startSourceEcho(t)
	poolPort, _ := startExitServer(t, "127.0.0.2")
	hop1Port, stopHop1 := startExitServer(t, "127.0.0.3")
	hop2Port, _ := startExitServer(t, "127.0.0.4")
	namedPort, _ := startExitServer(t, "127.0.0.5")
	hop2Via, hop2Callers := startRecordingForwarder(t, fmt.Sprintf("127.0.0.1:%d", hop2Port))

	prof := routing.Profile{
		Tiers: []routing.Tier{{Routes: []routing.Route{
			{To: "chain", Match: []string{"127.0.0.10"}},
			{To: "own", Match: []string{"127.0.0.11"}},
		}}},
		Targets: &routing.Targets{
			Version: 1,
			Servers: []routing.TargetServer{
				{ID: "h1", Link: ssLoopback(hop1Port, "h1")},
				{ID: "h2", Link: "ss://chacha20-ietf-poly1305:pw@" + hop2Via + "#h2"},
				{ID: "own", Link: ssLoopback(namedPort, "own")},
			},
			Chains: []routing.TargetChain{{ID: "chain", Hops: []string{"h1", "h2"}}},
		},
	}
	if err := prof.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := BuildConfig([]string{ssLoopback(poolPort, "pool")}, BalancerOptions{}, prof, "none")
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
	if err := inst.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inst.Close() })

	for _, c := range []struct{ name, address, exit string }{
		{"the pool", "127.0.0.12", "127.0.0.2"},
		{"a named server", "127.0.0.11", "127.0.0.5"},
		{"a chain", "127.0.0.10", "127.0.0.4"},
	} {
		got, err := exitOf(inst, c.address, echoPort)
		if err != nil || got != c.exit {
			t.Errorf("%s: the echo saw %q (%v), want %s", c.name, got, err, c.exit)
		}
	}
	if callers := hop2Callers(); len(callers) != 1 || callers[0] != "127.0.0.3" {
		t.Errorf("the chain's exit was reached from %v, want from hop 1 (127.0.0.3) only", callers)
	}

	stopHop1()
	if got, err := exitOf(inst, "127.0.0.10", echoPort); err == nil {
		t.Errorf("with hop 1 down the chain reached the echo as %q", got)
	}
	if callers := hop2Callers(); len(callers) != 1 {
		t.Errorf("the chain's exit was reached again from %v with hop 1 down", callers)
	}
}

func chainProfile(entry, later string) routing.Profile {
	return routing.Profile{
		Tiers: []routing.Tier{{Routes: []routing.Route{{To: "c1", Match: []string{"full:c.example"}}}}},
		Targets: &routing.Targets{
			Version: 1,
			Servers: []routing.TargetServer{{ID: "a", Link: entry}, {ID: "b", Link: later}},
			Chains:  []routing.TargetChain{{ID: "c1", Hops: []string{"a", "b"}}},
		},
	}
}

const downloadExtra = `{"downloadSettings":{"address":"dl.example.com","port":443,"network":"xhttp","security":"tls","tlsSettings":{"serverName":"dl.example.com"},"xhttpSettings":{"path":"/d"}}}`

func xhttpLink(extra string) string {
	return "vless://11111111-1111-1111-1111-111111111111@later.example:443?type=xhttp&security=tls&path=/u&mode=packet-up&extra=" + url.QueryEscape(extra) + "#x"
}

// An xhttp hop's download leg is a connection of its own with its own socket
// options, so it has to dial through the hop before it too.
func TestNamedTargets_XhttpDownloadLegDialsThroughTheHopBefore(t *testing.T) {
	resolveAs(t, map[string]string{"one.example": "192.0.2.11"})
	res, err := BuildConfig([]string{poolLink}, BalancerOptions{}, chainProfile(linkOne, xhttpLink(downloadExtra)), "none")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := res.Config.Build(); err != nil {
		t.Fatalf("xray refused the config: %v", err)
	}
	hop := outboundByTag(t, res.Config, "rc-c1-1")
	if got := dialerProxyOf(hop); got != "rc-c1-0" {
		t.Fatalf("upload leg dialerProxy = %q", got)
	}
	var extra struct {
		DownloadSettings struct {
			Sockopt struct {
				DialerProxy string `json:"dialerProxy"`
			} `json:"sockopt"`
		} `json:"downloadSettings"`
	}
	if err := json.Unmarshal(hop.StreamSetting.XHTTPSettings.Extra, &extra); err != nil {
		t.Fatal(err)
	}
	if extra.DownloadSettings.Sockopt.DialerProxy != "rc-c1-0" {
		t.Errorf("download leg dialerProxy = %q, want rc-c1-0: %s", extra.DownloadSettings.Sockopt.DialerProxy, hop.StreamSetting.XHTTPSettings.Extra)
	}

	entry, err := BuildConfig([]string{poolLink}, BalancerOptions{}, chainProfile(xhttpLink(downloadExtra), linkOne), "none")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(outboundByTag(t, entry.Config, "rc-c1-0").StreamSetting.XHTTPSettings.Extra), "dialerProxy") {
		t.Error("the first hop is dialled by the client: its download leg is too")
	}
}

// xray looks an ECH config up itself with a socket of its own, so a hop after
// the first that needs the lookup would send it outside the hop before it.
func TestNamedTargets_LaterHopEchLookupIsRefused(t *testing.T) {
	resolveAs(t, map[string]string{"one.example": "192.0.2.11"})
	const vmessECH = "vmess://" + testVMessUUID + "@192.0.2.61:443?type=tcp&security=tls&sni=h.example&ech="
	lookup := vmessECH + "udp%3A%2F%2F192.0.2.62#v"
	list := vmessECH + "AEX%2BDQBBAAAgACA%3D#v"
	if _, err := BuildConfig([]string{poolLink}, BalancerOptions{}, chainProfile(linkOne, lookup), "none"); err == nil {
		t.Error("a later hop that queries for its ECH config must be refused")
	}
	if _, err := BuildConfig([]string{poolLink}, BalancerOptions{}, chainProfile(lookup, linkOne), "none"); err != nil {
		t.Errorf("the first hop is dialled by the client: %v", err)
	}
	if _, err := BuildConfig([]string{poolLink}, BalancerOptions{}, chainProfile(linkOne, list), "none"); err != nil {
		t.Errorf("a config list needs no lookup: %v", err)
	}
	downloadECH := strings.Replace(downloadExtra, `"serverName":"dl.example.com"`, `"serverName":"dl.example.com","echConfigList":"udp://192.0.2.62"`, 1)
	if _, err := BuildConfig([]string{poolLink}, BalancerOptions{}, chainProfile(linkOne, xhttpLink(downloadECH)), "none"); err == nil {
		t.Error("a download leg that queries for its ECH config must be refused too")
	}
}

// DialSystem resolves a domain by the socket options' strategies before it
// hands the dial to the dialer proxy, so a hop after the first keeps neither.
func TestNamedTargets_LaterHopSocketOptionsDoNotResolveLocally(t *testing.T) {
	resolveAs(t, map[string]string{"one.example": "192.0.2.11"})
	extra := strings.Replace(downloadExtra, `"network":"xhttp"`, `"network":"xhttp","sockopt":{"domainStrategy":"UseIP","addressPortStrategy":"SrvPortOnly","tcpKeepAliveInterval":15}`, 1)
	res, err := BuildConfig([]string{poolLink}, BalancerOptions{}, chainProfile(linkOne, xhttpLink(extra)), "none")
	if err != nil {
		t.Fatal(err)
	}
	hop := outboundByTag(t, res.Config, "rc-c1-1")
	var doc struct {
		DownloadSettings struct {
			Sockopt map[string]any `json:"sockopt"`
		} `json:"downloadSettings"`
	}
	if err := json.Unmarshal(hop.StreamSetting.XHTTPSettings.Extra, &doc); err != nil {
		t.Fatal(err)
	}
	sockopt := doc.DownloadSettings.Sockopt
	if sockopt["dialerProxy"] != "rc-c1-0" || sockopt["domainStrategy"] != nil || sockopt["addressPortStrategy"] != nil || sockopt["tcpKeepAliveInterval"] != float64(15) {
		t.Errorf("download leg sockopt = %v, want the dialer proxy and the keepalive only", sockopt)
	}

	own := xrayConf.OutboundDetourConfig{StreamSetting: &xrayConf.StreamConfig{SocketSettings: &xrayConf.SocketConfig{DomainStrategy: "UseIP", AddressPortStrategy: "SrvPortOnly"}}}
	if err := setDialerProxy(&own, "rc-c1-0"); err != nil {
		t.Fatal(err)
	}
	if got := own.StreamSetting.SocketSettings; got.DomainStrategy != "" || got.AddressPortStrategy != "" || got.DialerProxy != "rc-c1-0" {
		t.Errorf("hop sockopt = %+v", got)
	}
}
