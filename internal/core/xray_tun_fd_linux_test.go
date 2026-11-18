//go:build linux && !no_xray && !with_tun2socks && with_gvisor

package core

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/fdbased"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/xtls/xray-core/common/session"
	"golang.org/x/sys/unix"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
)

// fdPair is a datagram socketpair standing for the platform's TUN fd: the
// core takes one end as its TUN, a test's stack the other.
func fdPair(t *testing.T) (tunEnd, appEnd int) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	return pair[0], pair[1]
}

func openFiles(t *testing.T) (all, eventfds int) {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		all++
		if target, err := os.Readlink("/proc/self/fd/" + entry.Name()); err == nil && target == "anon_inode:[eventfd]" {
			eventfds++
		}
	}
	return all, eventfds
}

// waitForOpenFilesToSettle returns once the process holds no more files than
// before, or after a few seconds. A flow that crossed the stack leaves its
// outbound sockets to xray's teardown and a pipe of the runtime's splice pool to
// the next garbage collection, so their closing would land inside the next
// test's own count of open files.
func waitForOpenFilesToSettle(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		runtime.GC()
		all, _ := openFiles(t)
		if all <= before {
			return
		}
		if time.Now().After(deadline) {
			t.Logf("%d files are open after the test, %d before it", all, before)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The platform's fd carries a flow end to end, through the stack and the
// dispatcher, on the path Android takes: sing-tun makes no route of its own
// and closes only the copy it was handed.
func TestXrayTunLayer_CarriesTCPOverThePlatformsFd(t *testing.T) {
	filesBefore, _ := openFiles(t)
	t.Cleanup(func() { waitForOpenFilesToSettle(t, filesBefore) })
	prof := routing.Profile{Mode: routing.ModeDirectAll}
	inst := startTunInstance(t, prof, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, 0, tcpEcho(t))
	x := &CoreController{}
	tunEnd, appEnd := fdPair(t)
	if err := x.startXrayTunLayer(&tunCopy{fd: tunEnd}, xrayTunParams{instance: inst.Instance, sniffing: session.SniffingRequest{}, routing: prof, mark: x.sessionGen.Load()}); err != nil {
		t.Fatalf("start the layer: %v", err)
	}
	t.Cleanup(x.stopXrayTunLayer)

	link, err := fdbased.New(&fdbased.Options{FDs: []int{appEnd}, MTU: uint32(defaultTunMTU)})
	if err != nil {
		t.Fatal(err)
	}
	apps := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if err := apps.CreateNIC(1, link); err != nil {
		t.Fatal(err)
	}
	if err := apps.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4(tunTestApp.As4()).WithPrefix()}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	apps.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	t.Cleanup(func() {
		apps.Destroy()
		_ = unix.Close(appEnd)
	})

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, apps, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(tunTestDest.As4()), Port: 80}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial through the fd: %v", err)
	}
	requireTunEcho(t, conn, bytes.Repeat([]byte("0123456789abcdef"), 8*1024))
}

// Sessions that start and stop one after another leave no eventfd and no fd
// behind (B-0276): gVisor's inbound dispatchers each hold an eventfd that a
// close of the stack alone does not release.
func TestXrayTunLayer_LeavesNoEventfdsOrFdsAcrossSessions(t *testing.T) {
	prof := routing.Profile{Mode: routing.ModeDirectAll}
	inst := startTunInstance(t, prof, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, 0, nil)
	x := &CoreController{}
	session := func() {
		tunEnd, appEnd := fdPair(t)
		defer unix.Close(appEnd)
		if err := x.startXrayTunLayer(&tunCopy{fd: tunEnd}, xrayTunParams{instance: inst.Instance, routing: prof, mark: x.sessionGen.Load()}); err != nil {
			t.Fatalf("start the layer: %v", err)
		}
		x.stopXrayTunLayer()
	}
	session() // the first session warms what the runtime opens once
	allBefore, eventfdsBefore := openFiles(t)
	const rounds = 25
	for i := 0; i < rounds; i++ {
		session()
	}
	allAfter, eventfdsAfter := openFiles(t)
	t.Logf("eventfds %d -> %d, open fds %d -> %d over %d sessions", eventfdsBefore, eventfdsAfter, allBefore, allAfter, rounds)
	if eventfdsAfter != eventfdsBefore {
		t.Errorf("eventfds went from %d to %d over %d sessions", eventfdsBefore, eventfdsAfter, rounds)
	}
	if allAfter != allBefore {
		t.Errorf("open fds went from %d to %d over %d sessions", allBefore, allAfter, rounds)
	}
}
