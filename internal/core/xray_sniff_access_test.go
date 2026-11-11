//go:build !no_xray

package core

import (
	"net"
	"strings"
	"sync"
	"testing"

	xrayCommonLog "github.com/xtls/xray-core/common/log"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
)

type accessRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *accessRecorder) Handle(msg xrayCommonLog.Message) {
	if access, ok := msg.(*xrayCommonLog.AccessMessage); ok {
		r.mu.Lock()
		r.lines = append(r.lines, access.String())
		r.mu.Unlock()
	}
}

func (r *accessRecorder) last() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) == 0 {
		return ""
	}
	return r.lines[len(r.lines)-1]
}

// The access message names the domain xray found, whether it kept the dialed
// address (route-only sniffing) or replaced it (a fake IP).
func TestXrayAccessTarget_NamesTheSniffedDomain(t *testing.T) {
	seen := make(chan string, 8)
	socksPort := socksRecorder(t, seen)
	inst := startSniffInstanceDNS(t, routing.Profile{Mode: routing.ModeProxyAll}, socksPort,
		dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"127.0.0.1:1"}})
	recorder := &accessRecorder{}
	xrayCommonLog.RegisterHandler(recorder)
	t.Cleanup(registerCoreLogHandler)

	sniffing, err := xrayconfig.AppSniffing(true, false)
	if err != nil {
		t.Fatal(err)
	}
	x := &CoreController{}
	app, err := x.newXrayBridgeProxy(inst, xrayconfig.AppTrafficTag, sniffing, x.sessionGen.Load())
	if err != nil {
		t.Fatal(err)
	}

	sniffFlow(t, app, net.ParseIP("198.51.100.9"), 443, "tls", "named.example", seen)
	if got := recorder.last(); !strings.Contains(got, "tcp:named.example:443") {
		t.Errorf("route-only sniffed flow: access message %q does not name the domain", got)
	}

	fake := fakeAnswer(t, app, "fake.example", 1)
	if fake == nil {
		t.Fatal("fake DNS gave no address")
	}
	sniffFlow(t, app, fake, 443, "none", "", seen)
	if got := recorder.last(); !strings.Contains(got, "tcp:fake.example:443") || strings.Contains(got, fake.String()) {
		t.Errorf("fake-IP flow: access message %q does not name the domain", got)
	}
}
