package xrayconfig

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	D "github.com/miekg/dns"
	xnet "github.com/xtls/xray-core/common/net"
	xrayCore "github.com/xtls/xray-core/core"
	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// startShadowsocksServer runs a real xray shadowsocks server on loopback and
// returns the link that reaches it.
func startShadowsocksServer(t *testing.T) string {
	t.Helper()
	port, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	conf := fmt.Sprintf(`{"inbounds":[{"listen":"127.0.0.1","port":%d,"protocol":"shadowsocks","settings":{"method":"chacha20-ietf-poly1305","password":"pw","network":"tcp,udp"}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow"}]}}]}`, port)
	server, err := xrayCore.StartInstance("json", []byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return fmt.Sprintf("ss://chacha20-ietf-poly1305:pw@127.0.0.1:%d#live", port)
}

// startDNSOverTCP answers every A query with answer and counts the queries.
func startDNSOverTCP(t *testing.T, answer string) (string, *atomic.Int32) {
	t.Helper()
	var queries atomic.Int32
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	server := &D.Server{Listener: listener, NotifyStartedFunc: func() { close(started) }, Handler: D.HandlerFunc(func(w D.ResponseWriter, req *D.Msg) {
		queries.Add(1)
		reply := new(D.Msg)
		reply.SetReply(req)
		if q := req.Question[0]; q.Qtype == D.TypeA {
			reply.Answer = append(reply.Answer, &D.A{Hdr: D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP(answer).To4()})
		}
		_ = w.WriteMsg(reply)
	})}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	return "tcp://" + listener.Addr().String(), &queries
}

// startProbeTarget serves the observatory's probe and counts the requests.
func startProbeTarget(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var probes atomic.Int32
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return "http://" + listener.Addr().String() + "/", &probes
}

// With the first server dead and another alive, the lookups xray makes for its
// own routing leave through the live one, so a name an address rule matches is
// routed by its address instead of stalling on the dead server.
func TestApplyDNS_RoutingLookupsFollowTheBalancerPastADeadFirstServer(t *testing.T) {
	// xray's observatory reads its status without the lock, so this skips under -race.
	skipWhereObservatoryRaces(t)
	deadPort, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	links := []string{
		fmt.Sprintf("ss://chacha20-ietf-poly1305:pw@127.0.0.1:%d#dead", deadPort),
		startShadowsocksServer(t),
	}
	probeURL, probes := startProbeTarget(t)

	for _, c := range []struct{ dnsMode, strategy string }{
		{dnsconfig.ModeNormal, "IPIfNonMatch"}, {dnsconfig.ModeNormal, "IPOnDemand"},
		{dnsconfig.ModeFakeIP, "IPIfNonMatch"}, {dnsconfig.ModeFakeIP, "IPOnDemand"},
	} {
		strategy := c.strategy
		t.Run(c.dnsMode+"/"+strategy, func(t *testing.T) {
			probesBefore := probes.Load()
			dnsServer, queries := startDNSOverTCP(t, "192.0.2.5")
			prof := routing.Profile{
				Mode:           routing.ModeProxyAll,
				DomainStrategy: strategy,
				Tiers:          []routing.Tier{{Block: []string{"192.0.2.0/24"}}},
			}
			res, err := BuildConfig(links, BalancerOptions{ProbeURL: probeURL, ProbeIntervalSec: 600}, prof, "none")
			if err != nil {
				t.Fatal(err)
			}
			ApplyDNS(res.Config, dnsconfig.Config{Mode: c.dnsMode, Servers: []string{dnsServer}}, prof)
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

			// The balancer falls back to the first server until the observatory
			// has probed both.
			deadline := time.Now().Add(20 * time.Second)
			for probes.Load() == probesBefore && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			time.Sleep(500 * time.Millisecond)
			addressed := xnet.TCPDestination(xnet.ParseAddress("198.51.100.1"), 443)
			if got, err := pickRoute(inst, AppTrafficTag, addressed, ""); err != nil || got != "proxy-1" {
				t.Fatalf("balancer did not leave the dead server: %q, %v", got, err)
			}

			start := time.Now()
			got, err := pickRoute(inst, AppTrafficTag, xnet.TCPDestination(xnet.ParseAddress("lookup.test"), 443), "")
			if err != nil {
				t.Fatal(err)
			}
			if got != blockTag {
				t.Fatalf("lookup.test routed to %q after %s, want %q: the name did not resolve into the blocked range", got, time.Since(start), blockTag)
			}
			if queries.Load() == 0 {
				t.Fatal("the resolver was never asked")
			}
		})
	}
}

func lastRuleJSON(cfg *xrayConf.Config) string {
	rules := cfg.RouterConfig.RuleList
	return string(bytes.TrimSpace(rules[len(rules)-1]))
}

func TestApplyDNS_BalancerRuleSitsAfterTheTiers(t *testing.T) {
	links := []string{dnsTestLink, "vless://11111111-1111-1111-1111-111111111111@192.0.2.2:443?type=tcp&security=none"}
	const followRule = `{"type":"field","balancerTag":"vpn","inboundTag":["dns-internal"]}`
	cases := []struct {
		name    string
		links   []string
		dns     dnsconfig.Config
		prof    routing.Profile
		want    bool
		wantTag string
	}{
		{"normal", links, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, routing.Profile{Mode: routing.ModeProxyAll, Tiers: []routing.Tier{{Block: []string{"192.0.2.0/24"}}}}, true, dnsInternalTag},
		{"fake-ip", links, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}, routing.Profile{Mode: routing.ModeProxyAll, Tiers: []routing.Tier{{Block: []string{"192.0.2.0/24"}}}}, true, dnsInternalTag},
		{"fake-ip with a direct outbound", links, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}, routing.Profile{Mode: routing.ModeProxyAll, Tiers: []routing.Tier{{Direct: []string{"domain:example.com"}}}}, false, dnsInternalTag},
		{"single server", links[:1], dnsconfig.Config{Servers: []string{"1.1.1.1"}}, routing.Profile{Mode: routing.ModeProxyAll, Tiers: []routing.Tier{{Block: []string{"192.0.2.0/24"}}}}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := BuildConfig(c.links, BalancerOptions{}, c.prof, "none")
			if err != nil {
				t.Fatal(err)
			}
			ApplyDNS(res.Config, c.dns, c.prof)
			if c.want {
				if got := lastRuleJSON(res.Config); got != followRule {
					t.Fatalf("last rule = %s, want %s", got, followRule)
				}
			} else {
				for _, r := range res.Config.RouterConfig.RuleList {
					if bytes.Contains(r, []byte(`"balancerTag":"vpn","inboundTag":["dns-internal"]`)) {
						t.Fatalf("unexpected balancer rule for the internal lookups: %s", r)
					}
				}
			}
			if got := res.Config.DNSConfig.Tag; got != c.wantTag {
				t.Fatalf("DNS tag = %q, want %q", got, c.wantTag)
			}
		})
	}
}
