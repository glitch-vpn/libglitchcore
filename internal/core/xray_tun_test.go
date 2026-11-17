//go:build !no_xray && !with_tun2socks && with_gvisor

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/link/pipe"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	tun "github.com/metacubex/sing-tun"
	xrayCommonLog "github.com/xtls/xray-core/common/log"
	xrayCore "github.com/xtls/xray-core/core"
	xrayStats "github.com/xtls/xray-core/features/stats"
	xrayConf "github.com/xtls/xray-core/infra/conf"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
	"github.com/glitch-vpn/libglitchcore/internal/routing"
	"github.com/glitch-vpn/libglitchcore/internal/xrayconfig"
)

// The app's address on the TUN, and a public address it dials: the TUN stack
// bounces anything that is not global unicast back to the app, so a flow that
// is to reach a loopback server goes to this address and the direct outbound
// redirects it.
var (
	tunTestApp  = netip.MustParseAddr("10.10.0.2")
	tunTestDest = netip.MustParseAddr("203.0.113.10")
)

const tunTestMTU = 1420

// pipeTun is a TUN device whose far end is a link endpoint the test drives.
type pipeTun struct{ ep *pipe.Endpoint }

func (t *pipeTun) Read([]byte) (int, error)    { return 0, io.EOF }
func (t *pipeTun) Write(b []byte) (int, error) { return len(b), nil }
func (t *pipeTun) Close() error                { return nil }

func (t *pipeTun) WritePacket(pkt *stack.PacketBuffer) (int, error) {
	var pkts stack.PacketBufferList
	pkts.PushBack(pkt.Clone())
	n, err := t.ep.WritePackets(pkts)
	pkts.DecRef()
	if err != nil {
		return 0, errors.New(err.String())
	}
	return n, nil
}

func (t *pipeTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.ep, stack.NICOptions{}, nil
}

// channelTun is a TUN device on a channel endpoint, for a test that reads the
// stack's replies packet by packet.
type channelTun struct{ ep *channel.Endpoint }

func (t channelTun) Read([]byte) (int, error)                     { return 0, io.EOF }
func (t channelTun) Write(b []byte) (int, error)                  { return len(b), nil }
func (t channelTun) Close() error                                 { return nil }
func (t channelTun) WritePacket(*stack.PacketBuffer) (int, error) { return 0, nil }
func (t channelTun) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.ep, stack.NICOptions{}, nil
}

func tunTestOptions(mtu uint32) tun.Options {
	return tun.Options{Name: xrayTunName, MTU: mtu, Inet4Address: []netip.Prefix{xrayTunPrefix4}}
}

// tunApps is the app side of the TUN: a gVisor stack whose every packet
// crosses the pipe into the core's stack.
func tunApps(t *testing.T, appSide *pipe.Endpoint) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	if err := s.CreateNIC(1, appSide); err != nil {
		t.Fatalf("app NIC: %v", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFrom4(tunTestApp.As4()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("app address: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	t.Cleanup(s.Close)
	return s
}

// redirectFreedom sends every direct outbound to target.
func redirectFreedom(t *testing.T, cfg *xrayConf.Config, target net.Addr) {
	t.Helper()
	for i := range cfg.OutboundConfigs {
		ob := &cfg.OutboundConfigs[i]
		if ob.Protocol != "freedom" {
			continue
		}
		settings := map[string]any{}
		if ob.Settings != nil {
			if err := json.Unmarshal(*ob.Settings, &settings); err != nil {
				t.Fatal(err)
			}
		}
		settings["redirect"] = target.String()
		raw, _ := json.Marshal(settings)
		msg := json.RawMessage(raw)
		ob.Settings = &msg
	}
}

type tunInstance struct {
	*xrayCore.Instance
	trafficTags []string
}

func (i tunInstance) traffic() (rx, tx uint64) {
	mgr := i.GetFeature(xrayStats.ManagerType()).(xrayStats.Manager)
	return sumOutboundTraffic(xrayStatsSource{mgr}, i.trafficTags)
}

// startTunInstance runs xray as the session builds it: no inbound, stats on,
// the proxy outbound a SOCKS client to socksPort when that is set, every
// direct outbound redirected to redirect when that is set.
func startTunInstance(t *testing.T, prof routing.Profile, dns dnsconfig.Config, socksPort int, redirect net.Addr) tunInstance {
	t.Helper()
	res, err := xrayconfig.BuildConfig([]string{vlessTestLink}, xrayconfig.BalancerOptions{}, prof, "none")
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	if socksPort > 0 {
		for i := range res.Config.OutboundConfigs {
			if res.Config.OutboundConfigs[i].Tag == res.RouteTarget {
				settings := json.RawMessage(`{"servers":[{"address":"127.0.0.1","port":` + strconv.Itoa(socksPort) + `}]}`)
				res.Config.OutboundConfigs[i] = xrayConf.OutboundDetourConfig{Protocol: "socks", Tag: res.RouteTarget, Settings: &settings}
			}
		}
	}
	xrayconfig.ApplyDNS(res.Config, dns, prof)
	if redirect != nil {
		redirectFreedom(t, res.Config, redirect)
	}
	res.Config.Stats = &xrayConf.StatsConfig{}
	res.Config.Policy = &xrayConf.PolicyConfig{System: &xrayConf.SystemPolicy{
		StatsOutboundUplink: true, StatsOutboundDownlink: true,
	}}
	built, err := res.Config.Build()
	if err != nil {
		t.Fatalf("cfg.Build: %v", err)
	}
	inst, err := xrayCore.New(built)
	if err != nil {
		t.Fatalf("xray New: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("xray Start: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	return tunInstance{Instance: inst, trafficTags: res.TrafficTags}
}

type tunRig struct {
	x       *CoreController
	handler *xrayTunHandler
	apps    *stack.Stack
	appSide *pipe.Endpoint
}

// startTunRig runs the session's own handler on sing-tun's gVisor stack over
// a pipe, with the app's stack at its far end.
func startTunRig(t *testing.T, inst tunInstance, prof routing.Profile, mtu uint32, processName func(string, netip.AddrPort) (string, error)) *tunRig {
	t.Helper()
	x := &CoreController{}
	sniffing, err := xrayconfig.AppSniffing(true, prof.LocalNetworks)
	if err != nil {
		t.Fatal(err)
	}
	h, err := x.newXrayTunHandler(xrayTunParams{instance: inst.Instance, sniffing: sniffing, routing: prof, mark: x.sessionGen.Load()})
	if err != nil {
		t.Fatal(err)
	}
	h.split.rules = routing.ProcessRules(prof)
	h.split.processName = processName
	coreSide, appSide := pipe.New("", "", mtu)
	session, err := startXrayTunStack(&pipeTun{ep: coreSide}, tunTestOptions(mtu), h)
	if err != nil {
		t.Fatalf("start the TUN stack: %v", err)
	}
	t.Cleanup(session.close)
	return &tunRig{x: x, handler: h, apps: tunApps(t, appSide), appSide: appSide}
}

func (r *tunRig) dialTCP(t *testing.T, port uint16) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	return gonet.DialContextTCP(ctx, r.apps, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(tunTestDest.As4()), Port: port}, ipv4.ProtocolNumber)
}

func (r *tunRig) dialUDP(t *testing.T, dst netip.AddrPort) *gonet.UDPConn {
	t.Helper()
	conn, err := gonet.DialUDP(r.apps, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(dst.Addr().As4()), Port: dst.Port()}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial udp %s: %v", dst, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func (r *tunRig) udpFlowCount() int {
	r.handler.udpMu.Lock()
	defer r.handler.udpMu.Unlock()
	return len(r.handler.udpFlows)
}

func portOf(a net.Addr) uint16 { return addrPortOf(a).Port() }

// The whole payload crosses the stack at the TUN's MTU and comes back.
func requireTunEcho(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	defer conn.Close()
	go func() { _, _ = conn.Write(payload) }()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read the echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("the echo differs from what was sent")
	}
}

func TestXrayTun_CarriesTCPAndUDPAcrossTheStack(t *testing.T) {
	tcpServer, udpServer := tcpEcho(t), udpEcho(t)
	prof := routing.Profile{Mode: routing.ModeDirectAll}
	dns := dnsconfig.Config{Servers: []string{"1.1.1.1"}}

	tcpRig := startTunRig(t, startTunInstance(t, prof, dns, 0, tcpServer), prof, tunTestMTU, nil)
	conn, err := tcpRig.dialTCP(t, 80)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	requireTunEcho(t, conn, bytes.Repeat([]byte("0123456789abcdef"), 16*1024))

	udpRig := startTunRig(t, startTunInstance(t, prof, dns, 0, udpServer), prof, tunTestMTU, nil)
	dst := netip.AddrPortFrom(tunTestDest, 5000)
	pc := udpRig.dialUDP(t, dst)
	datagram := bytes.Repeat([]byte{7}, 1300)
	b := make([]byte, 2048)
	for i := 0; ; i++ {
		if i == 10 {
			t.Fatal("udp through the stack: no answer")
		}
		_, _ = pc.Write(datagram)
		_ = pc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, from, err := pc.ReadFrom(b)
		if err != nil {
			continue
		}
		if !bytes.Equal(b[:n], datagram) {
			t.Fatalf("udp read %d bytes, want the %d sent", n, len(datagram))
		}
		if from.String() != dst.String() {
			t.Fatalf("reply reads as from %s, want %s", from, dst)
		}
		break
	}
}

// The stack runs at the MTU the session was configured with: a payload of
// several segments crosses a TUN narrower than the default.
func TestXrayTun_CarriesTCPAtTheConfiguredMTU(t *testing.T) {
	t.Setenv("GLITCH_TUN2SOCKS_MTU", "1280")
	options, err := xrayTunOptions("android", xrayTunParams{tunFd: 7}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if options.MTU != 1280 {
		t.Fatalf("the TUN's MTU is %d, want the configured 1280", options.MTU)
	}
	prof := routing.Profile{Mode: routing.ModeDirectAll}
	rig := startTunRig(t, startTunInstance(t, prof, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, 0, tcpEcho(t)), prof, options.MTU, nil)
	conn, err := rig.dialTCP(t, 80)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	requireTunEcho(t, conn, bytes.Repeat([]byte("0123456789abcdef"), 4096))
}

// fake-ip: the app's :53 meets xray's DNS outbound through the app tag's rule,
// whichever resolver address the adapter's DNS names.
func TestXrayTun_AnswersTheAppsDNSWithFakeIPs(t *testing.T) {
	prof := routing.Profile{}
	rig := startTunRig(t, startTunInstance(t, prof, dnsconfig.Config{Mode: dnsconfig.ModeFakeIP, Servers: []string{"1.1.1.1"}}, 0, nil), prof, tunTestMTU, nil)
	resolver := netip.MustParseAddrPort("1.1.1.1:53")
	requireFakeIPAnswer(t, rig.dialUDP(t, resolver), net.UDPAddrFromAddrPort(resolver), "198.19.")
}

// An app a rule sends direct reaches the server through the direct outbound
// while the catch-all would tunnel; another app's flow takes the proxy, which
// leads nowhere here; a blocked app's flow is reset. The process is the one
// behind the flow's source, as the core's lookup names it.
func TestXrayTun_SplitsByProcess(t *testing.T) {
	prof := routing.Profile{
		Mode:  routing.ModeProxyAll,
		Tiers: []routing.Tier{{Direct: []string{"process:app.exe"}, Block: []string{"process:bad.exe"}}},
	}
	server := tcpEcho(t)
	exe := "app.exe"
	rig := startTunRig(t, startTunInstance(t, prof, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, 0, server), prof, tunTestMTU,
		func(network string, src netip.AddrPort) (string, error) {
			if network != "tcp" || src.Addr() != tunTestApp {
				return "", errors.New("unexpected flow")
			}
			return filepath.Join(string(filepath.Separator), "apps", exe), nil
		})

	conn, err := rig.dialTCP(t, 443)
	if err != nil {
		t.Fatalf("dial as app.exe: %v", err)
	}
	requireTunEcho(t, conn, []byte("process-direct"))

	exe = "other.exe"
	conn, err = rig.dialTCP(t, 443)
	if err != nil {
		t.Fatalf("dial as other.exe: %v", err)
	}
	_, _ = conn.Write([]byte("tunneled"))
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	if n, _ := conn.Read(make([]byte, 16)); n > 0 {
		t.Fatal("an app no rule names reached the server direct in proxy-all")
	}
	_ = conn.Close()

	exe = "bad.exe"
	conn, err = rig.dialTCP(t, 443)
	if err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		_ = conn.Close()
	}
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a blocked app's flow was not reset: %v", err)
	}
}

// Without a lookup of its own the handler asks the host who owns the source
// port, which is the core's procname.
func TestXrayTun_FindsTheProcessBehindASourcePortByDefault(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		if c, err := listener.Accept(); err == nil {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	self := strings.ToLower(filepath.Base(os.Args[0]))
	split := processSplit{rules: map[string]string{self: routing.TargetDirect}}
	if got := split.target("tcp", addrPortOf(conn.LocalAddr())); got != routing.TargetDirect {
		t.Skipf("the host's process lookup does not name this test binary (%q): target %q", self, got)
	}
}

// A UDP flow ends once it has been idle for the session's UDP timeout, which
// is the one the user set.
func TestXrayTun_EndsIdleUDPFlows(t *testing.T) {
	t.Setenv("GLITCH_TUN2SOCKS_UDP_TIMEOUT_SEC", "45")
	server := udpEcho(t)
	prof := routing.Profile{Mode: routing.ModeDirectAll}
	rig := startTunRig(t, startTunInstance(t, prof, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, 0, server), prof, tunTestMTU, nil)
	if rig.handler.udpTimeout != 45*time.Second {
		t.Fatalf("the handler's UDP timeout is %s, want the configured 45s", rig.handler.udpTimeout)
	}
	rig.handler.udpTimeout = 300 * time.Millisecond
	pc := rig.dialUDP(t, netip.AddrPortFrom(tunTestDest, portOf(server)))
	_, _ = pc.Write([]byte("x"))
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := pc.ReadFrom(make([]byte, 16)); err != nil {
		t.Fatalf("no echo: %v", err)
	}
	if flows := rig.udpFlowCount(); flows != 1 {
		t.Fatalf("%d flows while one is live, want 1", flows)
	}
	time.Sleep(time.Second)
	if flows := rig.udpFlowCount(); flows != 0 {
		t.Fatalf("%d flows after the UDP timeout, want 0", flows)
	}
}

// Once its session has ended the stack hands xray no flow.
func TestXrayTun_RefusesAfterItsSessionEnds(t *testing.T) {
	server := tcpEcho(t)
	prof := routing.Profile{Mode: routing.ModeDirectAll}
	rig := startTunRig(t, startTunInstance(t, prof, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, 0, server), prof, tunTestMTU, nil)
	rig.x.clearSessionState()
	conn, err := rig.dialTCP(t, 80)
	if err == nil {
		_, _ = conn.Write([]byte("late"))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(make([]byte, 8))
		_ = conn.Close()
		if n > 0 {
			t.Fatal("a flow after the session ended reached xray")
		}
	}
}

type packetRecorder struct{ packets chan []byte }

func (r *packetRecorder) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	r.packets <- pkt.ToView().ToSlice()
}

func (r *packetRecorder) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func echoRequest(src, dst netip.Addr, ident uint16) *stack.PacketBuffer {
	icmpLen := header.ICMPv4MinimumSize + 8
	b := make([]byte, header.IPv4MinimumSize+icmpLen)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	echo := header.ICMPv4(b[header.IPv4MinimumSize:])
	echo.SetType(header.ICMPv4Echo)
	echo.SetIdent(ident)
	echo.SetSequence(1)
	copy(echo.Payload(), "glitch!!")
	echo.SetChecksum(header.ICMPv4Checksum(echo, 0))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	pkt.NetworkProtocolNumber = ipv4.ProtocolNumber
	return pkt
}

// An echo request to an address beyond the TUN is dropped, not answered: a
// reply would show a latency that crossed no tunnel, and a forward would leave
// from the device outside every rule. The stack does answer one to its own
// address, which shows it parsed the request.
func TestXrayTun_DropsEchoRequestsBeyondTheTUN(t *testing.T) {
	prof := routing.Profile{Mode: routing.ModeDirectAll}
	inst := startTunInstance(t, prof, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, 0, nil)
	x := &CoreController{}
	h, err := x.newXrayTunHandler(xrayTunParams{instance: inst.Instance, routing: prof, mark: x.sessionGen.Load()})
	if err != nil {
		t.Fatal(err)
	}
	coreSide, appSide := pipe.New("", "", tunTestMTU)
	replies := &packetRecorder{packets: make(chan []byte, 4)}
	appSide.Attach(replies)
	session, err := startXrayTunStack(&pipeTun{ep: coreSide}, tunTestOptions(tunTestMTU), h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.close)
	send := func(dst netip.Addr, ident uint16) {
		var pkts stack.PacketBufferList
		pkts.PushBack(echoRequest(tunTestApp, dst, ident))
		_, _ = appSide.WritePackets(pkts)
		pkts.DecRef()
	}

	send(xrayTunPrefix4.Addr(), 3)
	select {
	case p := <-replies.packets:
		if reply := header.ICMPv4(header.IPv4(p).Payload()); reply.Type() != header.ICMPv4EchoReply || reply.Ident() != 3 {
			t.Fatalf("the TUN's own address answered with ICMP type %d ident %d", reply.Type(), reply.Ident())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the stack did not answer an echo to its own address: the request was not parsed")
	}

	send(tunTestDest, 7)
	select {
	case p := <-replies.packets:
		t.Fatalf("an echo request beyond the TUN drew a reply: % x", p)
	case <-time.After(time.Second):
	}
}

// synSessionOnXrayStack is the session's stack on a test link, with the
// admission its production wiring arms.
func synSessionOnXrayStack(t *testing.T, x *CoreController) synSession {
	t.Helper()
	inst := startTunInstance(t, routing.Profile{Mode: routing.ModeDirectAll}, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, 0, nil)
	h, err := x.newXrayTunHandler(xrayTunParams{instance: inst.Instance, routing: routing.Profile{}, mark: x.sessionGen.Load()})
	if err != nil {
		t.Fatal(err)
	}
	link := channel.New(8, 1500, "")
	session, err := startXrayTunStack(channelTun{ep: link}, tunTestOptions(1500), h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.close)
	return synSession{
		send: func() {
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(synPacket(testDestination))})
			defer pkt.DecRef()
			link.InjectInbound(ipv6.ProtocolNumber, pkt)
		},
		answer: func(wait time.Duration) (byte, bool) {
			deadline := time.Now().Add(wait)
			for time.Now().Before(deadline) {
				if reply := link.Read(); reply != nil {
					defer reply.DecRef()
					return replyFlags(t, reply.ToView().AsSlice()), true
				}
				time.Sleep(10 * time.Millisecond)
			}
			return 0, false
		},
	}
}

// The xray stack judges an IPv6 SYN by what the exit is known to carry,
// before any handshake (B-0481).
func TestXrayTunStackJudgesIPv6FlowsByTheExit(t *testing.T) {
	checkStackJudgesByExit(t, func(t *testing.T, x *CoreController) synSession {
		setSingTunAdmission(x.admitTCPFlow)
		t.Cleanup(func() { setSingTunAdmission(nil) })
		return synSessionOnXrayStack(t, x)
	})
}

// A session's arming and stop reach the stack with no test installing the
// admission by hand.
func TestConfigureIPResolve_ArmsTheXrayTunStackAndStopDisarmsIt(t *testing.T) {
	x := &CoreController{}
	x.configureIPResolve(ipResolveConfig{enabled: true})
	armed := synSessionOnXrayStack(t, x)
	x.exitIPv6.Store(exitIPv6Absent)
	armed.send()
	if flags, answered := armed.answer(time.Second); !answered || flags&tcpFlagRST == 0 {
		t.Fatalf("an exit without IPv6: flags %#x (answered %v), want a reset", flags, answered)
	}
	x.stopIPResolve()
	x.exitIPv6.Store(exitIPv6Absent) // were the hook left in place, this would reset the SYN
	stopped := synSessionOnXrayStack(t, x)
	stopped.send()
	if flags, answered := stopped.answer(time.Second); !answered || flags&tcpFlagSYN == 0 {
		t.Fatalf("after the session stopped: flags %#x (answered %v), want SYN+ACK", flags, answered)
	}
}

// The inspector (402) records a flow the stack hands over, naming the address
// the app dialled, and the traffic the stats (300) read counts its bytes.
func TestXrayTun_FeedsTheInspectorAndTheStats(t *testing.T) {
	var mu sync.Mutex
	var conns []string
	prevInspect := connInspectEnabled.Load()
	connInspectEnabled.Store(true)
	t.Cleanup(func() { connInspectEnabled.Store(prevInspect) })
	setStatusSink(func(code int32, message string) {
		if code == ConnEvent {
			mu.Lock()
			conns = append(conns, message)
			mu.Unlock()
		}
	})
	t.Cleanup(func() { setStatusSink(nil) })
	prevController := globalController
	globalController = &CoreController{}
	t.Cleanup(func() { globalController = prevController })

	seen := make(chan string, 8)
	socksPort := socksRecorder(t, seen)
	prof := routing.Profile{Mode: routing.ModeProxyAll}
	inst := startTunInstance(t, prof, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, socksPort, nil)
	xrayCommonLog.RegisterHandler(xrayLogHandler{})
	t.Cleanup(registerCoreLogHandler)
	rig := startTunRig(t, inst, prof, tunTestMTU, nil)

	conn, err := rig.dialTCP(t, 443)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte{1}, 6000)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the inspector's record", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			if strings.Contains(c, tunTestDest.String()) {
				return true
			}
		}
		return false
	})
	waitFor(t, "the uplink the stats count", func() bool {
		_, tx := inst.traffic()
		return tx >= uint64(len(payload))
	})
}

// The exit echo and the liveness probe dial inside the instance under the
// exit-echo tag, which takes the proxy ahead of the tiers a direct-all
// profile would otherwise apply.
func TestXrayTunnelDial_ExitEchoTakesTheProxyAheadOfTheTiers(t *testing.T) {
	seen := make(chan string, 8)
	socksPort := socksRecorder(t, seen)
	inst := startTunInstance(t, routing.Profile{Mode: routing.ModeDirectAll}, dnsconfig.Config{Servers: []string{"1.1.1.1"}}, socksPort, nil)
	x := &CoreController{}
	x.xrayLife, x.xrayLifeCancel = context.WithCancel(context.Background())
	t.Cleanup(x.endXrayLife)
	dial := x.xrayTunnelDial(inst.Instance, xrayconfig.ExitEchoTag, x.sessionGen.Load())
	conn, err := dial(t.Context(), "tcp", "203.0.113.5:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	select {
	case got := <-seen:
		if got != "proxy:203.0.113.5" {
			t.Fatalf("the echo went %q, want the proxy", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the echo never reached the proxy")
	}
}

func TestXrayTunOptions_WindowsLetSingTunOwnTheAdapterRoutesAndDNS(t *testing.T) {
	servers := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.4")}
	p := xrayTunParams{dnsServer: "9.9.9.9", routing: routing.Profile{LocalNetworks: true}, tunFd: -1}
	options, err := xrayTunOptions("windows", p, servers)
	if err != nil {
		t.Fatal(err)
	}
	if !options.AutoRoute || !options.StrictRoute {
		t.Errorf("auto route %v, strict route %v: both are on, as on mihomo's TUN", options.AutoRoute, options.StrictRoute)
	}
	if options.DNSMode != tun.DNSModeHijack || len(options.DNSServers) != 1 || options.DNSServers[0] != netip.MustParseAddr("9.9.9.9") {
		t.Errorf("DNS mode %q servers %v, want the core's resolver hijacked in", options.DNSMode, options.DNSServers)
	}
	if len(options.Inet6Address) != 1 {
		t.Errorf("IPv6 on: addresses %v, want the TUN's IPv6 one", options.Inet6Address)
	}
	if options.FileDescriptor != 0 {
		t.Errorf("a Windows TUN carries fd %d", options.FileDescriptor)
	}

	ranges, err := options.BuildAutoRouteRanges(false)
	if err != nil {
		t.Fatal(err)
	}
	routed := func(addr string) bool {
		for _, r := range ranges {
			if r.Contains(netip.MustParseAddr(addr)) {
				return true
			}
		}
		return false
	}
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "203.0.113.9": true, "11.0.0.1": true,
		"192.0.2.1": false, "198.51.100.4": false, // the proxy servers
		"10.1.2.3": false, "172.16.9.9": false, "192.168.1.20": false, // local networks
	} {
		if routed(addr) != want {
			t.Errorf("%s routed into the TUN = %v, want %v", addr, !want, want)
		}
	}
}

func TestXrayTunOptions_WindowsKeepsLocalNetworksOnTheTUNUnlessTheProfileSaysOtherwise(t *testing.T) {
	options, err := xrayTunOptions("windows", xrayTunParams{routing: routing.Profile{DisableIPv6: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Inet4RouteExcludeAddress) != 0 {
		t.Errorf("excluded %v with local networks off and no servers", options.Inet4RouteExcludeAddress)
	}
	if len(options.Inet6Address) != 0 {
		t.Errorf("IPv6 off: addresses %v; strict route blocks IPv6 only while the TUN has none", options.Inet6Address)
	}
}

func TestXrayTunOptions_AFdIsTheWholeSetupWhereThePlatformRoutes(t *testing.T) {
	options, err := xrayTunOptions("android", xrayTunParams{tunFd: 42, routing: routing.Profile{LocalNetworks: true}, dnsServer: "9.9.9.9"}, []netip.Addr{netip.MustParseAddr("192.0.2.1")})
	if err != nil {
		t.Fatal(err)
	}
	if options.FileDescriptor != 42 {
		t.Errorf("fd %d, want the platform's 42", options.FileDescriptor)
	}
	if options.AutoRoute || options.StrictRoute || len(options.Inet4RouteExcludeAddress) != 0 || len(options.DNSServers) != 0 {
		t.Errorf("options %+v: sing-tun must not route, exclude or set DNS where VpnService does", options)
	}
	if _, err := xrayTunOptions("android", xrayTunParams{tunFd: -1}, nil); err == nil {
		t.Error("a start with no fd opened a TUN")
	}
}

func TestServerAddresses_ResolvesNamesAndKeepsOnlyIPv4Once(t *testing.T) {
	lookups := 0
	lookup := func(_ context.Context, host string) ([]net.IP, error) {
		lookups++
		switch host {
		case "vpn.example":
			return []net.IP{net.ParseIP("203.0.113.7"), net.ParseIP("2001:db8::7")}, nil
		}
		return nil, errors.New("no such host")
	}
	got := serverAddresses([]string{"192.0.2.1", "vpn.example", "192.0.2.1", "gone.example", "", "2001:db8::1", "203.0.113.7"}, lookup)
	want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.7")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("servers %v, want %v", got, want)
	}
	if lookups != 2 {
		t.Errorf("%d lookups, want one for each name", lookups)
	}
}

// The layer's own stop leaves nothing behind and a second one is harmless.
func TestStopXrayTunLayer_WithoutASessionIsANoOp(t *testing.T) {
	x := &CoreController{}
	x.stopXrayTunLayer()
	x.stopXrayTunLayer()
}
