//go:build !no_xray && !with_tun2socks && with_gvisor

package core

import (
	"bytes"
	"log"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	tun "github.com/metacubex/sing-tun"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// blockingTun is a device whose Close does not return until the test says so.
type blockingTun struct {
	channelTun
	closeReturns chan struct{}
}

func (d blockingTun) Close() error {
	<-d.closeReturns
	return nil
}

// A stop gives up on a Close that hangs and reports the layer stopped. The
// next start, whichever engine it is, must still not create the one adapter
// until that Close has returned.
func TestXrayTunLayer_NextAdapterWaitsForALateClose(t *testing.T) {
	prevNew, prevStopWait, prevWait := newTunDevice, tunLayerStopWait, desktopAdapterWait
	t.Cleanup(func() { newTunDevice, tunLayerStopWait, desktopAdapterWait = prevNew, prevStopWait, prevWait })
	tunLayerStopWait = 50 * time.Millisecond
	desktopAdapterWait = 10 * time.Second

	closeReturns := make(chan struct{})
	var created atomic.Int32
	newTunDevice = func(tun.Options) (tun.Tun, error) {
		created.Add(1)
		return blockingTun{channelTun: channelTun{ep: channel.New(8, 1500, "")}, closeReturns: closeReturns}, nil
	}

	x := &CoreController{}
	inst := startTunInstance(t, routing.Profile{Mode: routing.ModeDirectAll}, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, 0, nil)
	handler, err := x.newXrayTunHandler(xrayTunParams{instance: inst.Instance, routing: routing.Profile{}, mark: x.sessionGen.Load()})
	if err != nil {
		t.Fatal(err)
	}
	options := tunTestOptions(1500)
	device, release, err := openXrayTun(options)
	if err != nil {
		t.Fatal(err)
	}
	session, err := startXrayTunStack(device, options, handler)
	if err != nil {
		t.Fatal(err)
	}
	session.device, session.releaseAdapter = device, release
	x.xrayTun = session

	stopped := make(chan struct{})
	go func() {
		x.stopXrayTunLayer()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the stop did not give up on a Close that hangs")
	}

	next := make(chan func())
	go func() {
		_, releaseNext, err := openXrayTun(options)
		if err != nil {
			t.Errorf("the next adapter: %v", err)
			releaseNext = func() {}
		}
		next <- releaseNext
	}()
	select {
	case <-next:
		t.Fatalf("the next adapter was created (%d created) while the last one's Close had not returned", created.Load())
	case <-time.After(300 * time.Millisecond):
	}

	close(closeReturns)
	select {
	case releaseNext := <-next:
		releaseNext()
	case <-time.After(5 * time.Second):
		t.Fatal("the next adapter was not created after the Close returned")
	}
	if created.Load() != 2 {
		t.Fatalf("%d adapters created, want 2", created.Load())
	}
}

// The layer's start and stop each write their steps' durations to the core's
// log, and the lines hold no address, port or host name.
func TestXrayTunLayer_LogsTheDurationOfEachStep(t *testing.T) {
	prevNew := newTunDevice
	t.Cleanup(func() { newTunDevice = prevNew })
	newTunDevice = func(tun.Options) (tun.Tun, error) {
		return channelTun{ep: channel.New(8, 1500, "")}, nil
	}
	var logged bytes.Buffer
	prevWriter, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&logged)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevWriter); log.SetFlags(prevFlags) })

	x := &CoreController{}
	inst := startTunInstance(t, routing.Profile{Mode: routing.ModeDirectAll}, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, 0, nil)
	handler, err := x.newXrayTunHandler(xrayTunParams{instance: inst.Instance, routing: routing.Profile{}, mark: x.sessionGen.Load()})
	if err != nil {
		t.Fatal(err)
	}
	options := tunTestOptions(1500)
	device, release, err := openXrayTun(options)
	if err != nil {
		t.Fatal(err)
	}
	session, err := startXrayTunStack(device, options, handler)
	if err != nil {
		t.Fatal(err)
	}
	session.device, session.releaseAdapter = device, release
	x.xrayTun = session
	x.stopXrayTunLayer()

	out := logged.String()
	for _, step := range []string{
		"[tun] adapter gate waited in ",
		"[tun] adapter opened and configured in ",
		"[tun] stack started in ",
		"[tun] stack closed in ",
		"[tun] UDP flows closed in ",
		"[tun] device closed in ",
	} {
		if !strings.Contains(out, step) {
			t.Errorf("log lacks %q:\n%s", step, out)
		}
	}
	if leak := regexp.MustCompile(`\d+\.\d+\.\d+\.\d+|:\d|[A-Za-z0-9-]+\.[A-Za-z]{2,}`).FindString(out); leak != "" {
		t.Errorf("log holds %q, which reads as an address, port or host name:\n%s", leak, out)
	}
}
