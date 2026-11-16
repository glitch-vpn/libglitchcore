//go:build !no_mihomo && !no_xray

package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/hub/executor"
	D "github.com/miekg/dns"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/loopbackport"
	"github.com/glitch-vpn/libglitchcore/internal/mihomoconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// Through an exit that carries, the probe held to IPv4 finds its host's
// address through that exit and reaches the host, so a WireGuard session's
// link comes up. A direct adapter stands in for the WireGuard exit under the
// same name.
func TestMihomoProbeDial_AWireGuardProbeReachesItsHostThroughTheExit(t *testing.T) {
	skipWhereMihomoRaces(t)
	mihomoTestHome(t)
	t.Cleanup(mihomoTeardown)

	var addressQueries atomic.Int32
	resolverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &D.Server{PacketConn: resolverConn, Handler: D.HandlerFunc(func(w D.ResponseWriter, query *D.Msg) {
		answer := new(D.Msg)
		answer.SetReply(query)
		if query.Question[0].Qtype == D.TypeA {
			addressQueries.Add(1)
			record, _ := D.NewRR(query.Question[0].Name + " 60 IN A 127.0.0.1")
			answer.Answer = append(answer.Answer, record)
		}
		_ = w.WriteMsg(answer)
	})}
	go func() { _ = resolver.ActivateAndServe() }()
	t.Cleanup(func() { _ = resolver.Shutdown() })
	pingHost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(pingHost.Close)
	_, pingPort, _ := net.SplitHostPort(pingHost.Listener.Addr().String())

	deadPort, err := loopbackport.Pick()
	if err != nil {
		t.Fatal(err)
	}
	key := func(fill byte) string {
		return url.QueryEscape(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32)))
	}
	links := []string{"wireguard://" + key(0x11) + "@127.0.0.1:" + strconv.Itoa(deadPort) +
		"?publickey=" + key(0x22) + "&address=10.66.0.2/32"}
	inbound := mihomoconfig.Inbound{Bridge: true, DNS: dnsconfig.Config{
		Mode:    dnsconfig.ModeFakeIP,
		Servers: []string{resolverConn.LocalAddr().String()},
	}}
	cfg, err := mihomoconfig.BuildConfig(links, inbound, mihomoconfig.Options{}, routing.Profile{Mode: routing.ModeDirectAll})
	if err != nil {
		t.Fatal(err)
	}
	target := mihomoconfig.Target(links)
	carrying, err := adapter.ParseProxy(map[string]any{"name": target, "type": "direct"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Proxies[target] = carrying
	executor.ApplyConfig(cfg, true)

	x := &CoreController{}
	x.exitIPv6.Store(exitIPv6Pending)
	probe := tunnelProber(x.mihomoProbeDial(links, inbound, x.sessionGen.Load()), "http://probe.test:"+pingPort+"/generate_204")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := probe(ctx); err != nil {
		t.Fatalf("probe through a carrying exit: %v", err)
	}
	if got := addressQueries.Load(); got == 0 {
		t.Fatal("the probe reached its host without asking the session's resolver through the exit")
	}
}
