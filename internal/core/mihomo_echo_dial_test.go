//go:build !no_mihomo

package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	mihomoTunnel "github.com/metacubex/mihomo/tunnel"
)

// refusingExit is an outbound whose dial fails at once, the way an exit with no
// IPv6 fails a WireGuard flow to an IPv6 destination.
type refusingExit struct {
	*outbound.Base
	dials atomic.Int32
}

func (e *refusingExit) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	e.dials.Add(1)
	return nil, errors.New("dial tcp [2607:f8b0::1]:443: connect: network is unreachable")
}

// mihomo's tunnel handler redials a failed outbound ten times with a pause that
// grows from a few milliseconds to a second. An echo or a probe pinned to an
// exit that refuses at once must reach it once.
func TestMihomoTunnelDial_APinnedProxyThatRefusesIsDialledOnce(t *testing.T) {
	exit := &refusingExit{Base: outbound.NewBase(outbound.BaseOption{Name: "exit", Type: C.Direct})}
	prevProxies, prevStatus := mihomoTunnel.Proxies(), mihomoTunnel.Status()
	mihomoTunnel.UpdateProxies(map[string]C.Proxy{"exit": adapter.NewProxy(exit)}, nil)
	mihomoTunnel.OnInnerLoading()
	t.Cleanup(func() {
		mihomoTunnel.UpdateProxies(prevProxies, nil)
		switch prevStatus {
		case mihomoTunnel.Running:
			mihomoTunnel.OnRunning()
		case mihomoTunnel.Inner:
			mihomoTunnel.OnInnerLoading()
		default:
			mihomoTunnel.OnSuspend()
		}
	})

	x := &CoreController{}
	dial := x.mihomoTunnelDial("exit", x.sessionGen.Load())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := fetchIPEcho(ctx, "https://api6.example", dial, true); err == nil {
		t.Fatal("an exit that refuses answered the echo")
	}
	time.Sleep(500 * time.Millisecond)
	if n := exit.dials.Load(); n != 1 {
		t.Fatalf("the exit was dialled %d times for one echo, want 1", n)
	}
}
