//go:build !no_xray

package core

import (
	"net"
	"strconv"
	"testing"

	D "github.com/miekg/dns"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
)

// An app a rule sends direct by process still meets the blocks: a flow naming
// a blocked site is refused, and one to anywhere else is dialled direct.
func TestXrayBridge_ProcessDirectFlowsMeetTheBlocks(t *testing.T) {
	const lanHost = "127.0.0.5"
	seen := make(chan string, 8)
	socksPort := socksRecorder(t, seen)
	directPort := directRecorder(t, lanHost, seen)
	prof := routing.Profile{
		Mode:  routing.ModeProxyAll,
		Tiers: []routing.Tier{{Block: []string{"domain:blocked.test"}, Direct: []string{"process:app.exe"}}},
	}
	inst := startSniffInstance(t, prof, socksPort)
	sniffing, err := xrayconfig.AppSniffing(true, prof.LocalNetworks)
	if err != nil {
		t.Fatal(err)
	}
	x := &CoreController{}
	forceDirect, err := x.newXrayBridgeProxy(inst, xrayconfig.ForceDirectTag, sniffing, x.sessionGen.Load())
	if err != nil {
		t.Fatal(err)
	}
	if got := sniffFlow(t, forceDirect, net.ParseIP("198.51.100.9"), 443, "tls", "blocked.test", seen); got != "none" {
		t.Errorf("process-direct flow naming blocked.test -> %s, want it blocked", got)
	}
	if got := sniffFlow(t, forceDirect, net.ParseIP(lanHost), directPort, "tls", "open.test", seen); got != "direct:"+lanHost {
		t.Errorf("process-direct flow naming open.test -> %s, want it dialled direct", got)
	}
}

// A name no block names, but which resolves to an address a block holds, is
// refused for a process-direct app too.
func TestXrayBridge_ProcessDirectFlowsMeetAddressBlocksByName(t *testing.T) {
	seen := make(chan string, 8)
	socksPort := socksRecorder(t, seen)
	directPort := directRecorder(t, "127.0.0.6", seen)
	// Whatever dials the blocked address would be seen at it.
	blocked, err := net.Listen("tcp", net.JoinHostPort("127.0.0.5", strconv.Itoa(directPort)))
	if err != nil {
		t.Skipf("listen on 127.0.0.5: %v", err)
	}
	t.Cleanup(func() { _ = blocked.Close() })
	go func() {
		for {
			c, err := blocked.Accept()
			if err != nil {
				return
			}
			seen <- "direct:127.0.0.5"
			_ = c.Close()
		}
	}()
	prof := routing.Profile{
		Mode:  routing.ModeProxyAll,
		Tiers: []routing.Tier{{Block: []string{"127.0.0.5/32"}, Direct: []string{"process:app.exe"}}},
	}
	dns := dnsconfig.Config{
		Mode:    dnsconfig.ModeFakeIP,
		Servers: []string{answerDNS(t, map[string]string{"blocked-address.test.": "127.0.0.5", "open-address.test.": "127.0.0.6"})},
	}
	inst := startSniffInstanceDNS(t, prof, socksPort, dns)
	sniffing, err := xrayconfig.AppSniffing(true, prof.LocalNetworks)
	if err != nil {
		t.Fatal(err)
	}
	x := &CoreController{}
	app, err := x.newXrayBridgeProxy(inst, xrayconfig.AppTrafficTag, sniffing, x.sessionGen.Load())
	if err != nil {
		t.Fatal(err)
	}
	forceDirect, err := x.newXrayBridgeProxy(inst, xrayconfig.ForceDirectTag, sniffing, x.sessionGen.Load())
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"blocked-address.test": "none", "open-address.test": "direct:127.0.0.6"} {
		ip := fakeAnswer(t, app, name, D.TypeA)
		if ip == nil {
			t.Fatalf("no fake answer for %s", name)
		}
		got := sniffFlow(t, forceDirect, ip, directPort, "none", "", seen)
		if got != want {
			t.Errorf("process-direct flow to %s -> %s, want %s", name, got, want)
		}
	}
}
