package core

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glitch-vpn/libglitchcore/internal/liveness"
	"github.com/glitch-vpn/libglitchcore/internal/serverinfo"
)

func TestAdmitTCPFlow(t *testing.T) {
	cases := []struct {
		name        string
		state       int32
		localDirect bool
		dest        string
		want        tcpVerdict
	}{
		{"nothing to judge, IPv6", exitIPv6Unknown, false, "[2607:f8b0::1]:443", tcpAdmit},
		{"echo pending, IPv6", exitIPv6Pending, false, "[2607:f8b0::1]:443", tcpDrop},
		{"IPv6 exit, IPv6", exitIPv6Carried, false, "[2607:f8b0::1]:443", tcpAdmit},
		{"no IPv6 exit, IPv6", exitIPv6Absent, false, "[2607:f8b0::1]:443", tcpReset},
		{"no IPv6 exit, fake-ip IPv6", exitIPv6Absent, true, "[fc00::1]:443", tcpReset},
		{"no IPv6 exit, LAN unique local, local networks direct", exitIPv6Absent, true, "[fd12:3456::1]:443", tcpAdmit},
		{"no IPv6 exit, LAN unique local, local networks tunnelled", exitIPv6Absent, false, "[fd12:3456::1]:443", tcpReset},
		{"echo pending, LAN unique local, local networks direct", exitIPv6Pending, true, "[fd12:3456::1]:443", tcpAdmit},
		{"no IPv6 exit, IPv4", exitIPv6Absent, false, "203.0.113.7:443", tcpAdmit},
		{"no IPv6 exit, mapped IPv4", exitIPv6Absent, false, "[::ffff:203.0.113.7]:443", tcpAdmit},
		{"no IPv6 exit, link-local", exitIPv6Absent, false, "[fe80::1]:443", tcpAdmit},
		{"no IPv6 exit, multicast", exitIPv6Absent, false, "[ff02::1]:443", tcpAdmit},
	}
	for _, c := range cases {
		x := &CoreController{}
		x.ipResolve.Store(ipResolveConfig{enabled: true, localNetworksDirect: c.localDirect})
		x.exitIPv6.Store(c.state)
		if got := x.admitTCPFlow(netip.MustParseAddrPort(c.dest)); got != c.want {
			t.Errorf("%s: verdict = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestEchoFinishedV6(t *testing.T) {
	cases := []struct {
		name       string
		outcome    echoV6Outcome
		linkUp     bool
		perConn    bool
		staleRound bool
		from       int32
		want       int32
	}{
		{"answered", echoV6Carried, true, false, false, exitIPv6Pending, exitIPv6Carried},
		{"answered with the link not yet up", echoV6Carried, false, false, false, exitIPv6Pending, exitIPv6Carried},
		{"failed on the way, IPv4 got through, link up", echoV6Unreachable, true, false, false, exitIPv6Pending, exitIPv6Absent},
		{"failed on the way, IPv4 got through, link not up", echoV6Unreachable, false, false, false, exitIPv6Pending, exitIPv6Unknown},
		{"both failed on the way, link up", echoV6Inconclusive, true, false, false, exitIPv6Pending, exitIPv6Unknown},
		{"both failed on the way, after the wait ended", echoV6Inconclusive, true, false, false, exitIPv6Unknown, exitIPv6Unknown},
		{"answered after the wait ended", echoV6Carried, true, false, false, exitIPv6Unknown, exitIPv6Carried},
		{"servers picked per connection", echoV6Unreachable, true, true, false, exitIPv6Pending, exitIPv6Pending},
		{"round of an earlier exit", echoV6Unreachable, true, false, true, exitIPv6Pending, exitIPv6Pending},
	}
	for _, c := range cases {
		x := &CoreController{}
		x.exitIPv6.Store(c.from)
		x.exitPerConnection.Store(c.perConn)
		if c.linkUp {
			x.linkState.Store(int32(liveness.StateUp))
		}
		gen := x.ipGen.Load()
		if c.staleRound {
			x.ipGen.Add(1)
		}
		x.echoFinishedV6(gen, c.outcome)
		if got := x.exitIPv6.Load(); got != c.want {
			t.Errorf("%s: state = %d, want %d", c.name, got, c.want)
		}
	}
}

// An echo that reached api6.ipify.org and got a status back shows an exit that
// carries IPv6; one that failed on the way shows one that does not only when
// the round's IPv4 echo got through.
func TestFetchExternalIPs_ReportsHowTheIPv6EchoEnded(t *testing.T) {
	status := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(status.Close)
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "api6.example:443" || addr == "api4.example:443" {
			return nil, errors.New("dial tcp: connect: network is unreachable")
		}
		return directTestDial(ctx, network, addr)
	}
	for _, c := range []struct {
		name  string
		urlV4 string
		urlV6 string
		want  echoV6Outcome
	}{
		{"503", status.URL, status.URL, echoV6Carried},
		{"IPv6 unreachable, IPv4 answered", status.URL, "https://api6.example", echoV6Unreachable},
		{"both unreachable", "https://api4.example", "https://api6.example", echoV6Inconclusive},
	} {
		got := make(chan echoV6Outcome, 1)
		fetchExternalIPs(ipResolveConfig{enabled: true, urlV4: c.urlV4, urlV6: c.urlV6, dial: dial}, nil,
			func(outcome echoV6Outcome) { got <- outcome })
		if outcome := <-got; outcome != c.want {
			t.Errorf("%s: outcome = %d, want %d", c.name, outcome, c.want)
		}
	}
}

// An exit with no IPv6 answers the IPv6 echo with "network is unreachable", as
// the engine's dial reports it; a retry loop would dial each family twice.
func TestFetchExternalIPs_OneDialPerFamilyThroughAnExitWithoutIPv6(t *testing.T) {
	var mu sync.Mutex
	dialed := map[string]int{}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed[addr]++
		mu.Unlock()
		if addr == "api6.example:443" {
			return nil, errors.New("dial tcp [2607:f8b0::1]:443: connect: network is unreachable")
		}
		return nil, errors.New("v4 is not under test")
	}
	st := fetchExternalIPs(ipResolveConfig{
		enabled: true, urlV4: "https://api4.example", urlV6: "https://api6.example", dial: dial,
	}, nil, nil)
	if st.IPv6 != "" || st.IPv6Error == "" {
		t.Fatalf("IPv6 = %+v", st)
	}
	mu.Lock()
	defer mu.Unlock()
	if dialed["api6.example:443"] != 1 || dialed["api4.example:443"] != 1 {
		t.Fatalf("dials = %v, want one per family", dialed)
	}
}

// exitSession is a controller armed the way an engine start arms it, over an
// exit whose IPv6 echo fails with "network is unreachable" and whose IPv4 echo
// answers after v4Delay.
type exitSession struct {
	x       *CoreController
	events  func() []string
	v6Dials atomic.Int32
	v4Dials atomic.Int32
	v4Delay time.Duration
	// v4Err, when set, is what the IPv4 echo's dial fails with.
	v4Err error
	// beforeV6Fails, when set, holds the nth IPv6 echo dial before it fails.
	beforeV6Fails func(call int32)
}

func newExitSession(t *testing.T, v4Delay time.Duration, selection *serverinfo.Selection) *exitSession {
	t.Helper()
	s := &exitSession{x: &CoreController{}, v4Delay: v4Delay}
	s.events = collectEvents(t, IPEvent)
	srv4 := echoServer(t, "203.0.113.7")
	if selection != nil {
		s.x.setServerSelection(selection)
	}
	s.x.linkState.Store(int32(liveness.StateUp))
	s.x.configureIPResolve(ipResolveConfig{
		enabled: true, urlV4: srv4.URL, urlV6: "https://api6.example",
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == "api6.example:443" {
				call := s.v6Dials.Add(1)
				if s.beforeV6Fails != nil {
					s.beforeV6Fails(call)
				}
				return nil, errors.New("dial tcp [2607:f8b0::1]:443: connect: network is unreachable")
			}
			s.v4Dials.Add(1)
			time.Sleep(s.v4Delay)
			if s.v4Err != nil {
				return nil, s.v4Err
			}
			return directTestDial(ctx, network, addr)
		},
	})
	t.Cleanup(s.x.stopIPResolve)
	return s
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !ok() {
		t.Fatalf("timed out waiting for %s", what)
	}
}

func selectionOn(strategy string, total, picked int) *serverinfo.Selection {
	sel := &serverinfo.Selection{Engine: "mihomo", Strategy: strategy, Total: total}
	for i := 0; i < total; i++ {
		sel.Servers = append(sel.Servers, serverinfo.Server{Index: i, Host: "198.51.100." + strconv.Itoa(i+1), Port: 443, Protocol: "awg"})
	}
	if picked >= 0 {
		server := sel.Servers[picked]
		sel.Selected = &server
	}
	return sel
}

func TestTriggerIPResolve_AsksForIPv6OncePerExit(t *testing.T) {
	s := newExitSession(t, 0, selectionOn("", 1, 0))
	if got := s.x.exitIPv6.Load(); got != exitIPv6Pending {
		t.Fatalf("state before the echo = %d, want pending", got)
	}

	s.x.triggerIPResolve("link-up")
	waitFor(t, "the IPEvent", func() bool { return len(s.events()) == 1 })
	if got := s.x.exitIPv6.Load(); got != exitIPv6Absent {
		t.Fatalf("state after the echo = %d, want absent", got)
	}

	s.x.triggerIPResolve("link-up")
	waitFor(t, "the second round's IPv4 echo", func() bool { return s.v4Dials.Load() == 2 })
	time.Sleep(200 * time.Millisecond)
	if n := s.v6Dials.Load(); n != 1 {
		t.Fatalf("IPv6 echo dials after a second round = %d, want 1", n)
	}
}

// A server change while an echo round is in flight must not leave the round's
// answer, which is the old exit's, standing for the new one.
func TestSetServerSelection_ADifferentServerMidRoundAsksIPv6Again(t *testing.T) {
	s := newExitSession(t, 800*time.Millisecond, selectionOn("url-test", 2, 0))
	s.x.triggerIPResolve("link-up")
	waitFor(t, "the old exit's IPv6 answer", func() bool { return s.x.exitIPv6.Load() == exitIPv6Absent })

	s.x.setServerSelection(selectionOn("url-test", 2, 1))
	if got := s.x.exitIPv6.Load(); got != exitIPv6Pending {
		t.Fatalf("state right after the switch = %d, want pending", got)
	}
	waitFor(t, "the new exit's IPv6 echo", func() bool { return s.v6Dials.Load() == 2 })
	waitFor(t, "the new exit's answer", func() bool { return s.x.exitIPv6.Load() == exitIPv6Absent })
}

// The IPv6 echo of the old exit may still be in flight when the server changes;
// its failure says nothing about the new exit.
func TestSetServerSelection_AnIPv6EchoOfTheOldServerDoesNotJudgeTheNewOne(t *testing.T) {
	s := newExitSession(t, 0, selectionOn("url-test", 2, 0))
	release := [3]chan struct{}{nil, make(chan struct{}), make(chan struct{})}
	s.beforeV6Fails = func(call int32) { <-release[call] }
	s.x.triggerIPResolve("link-up")
	waitFor(t, "the old exit's IPv6 echo", func() bool { return s.v6Dials.Load() == 1 })

	s.x.setServerSelection(selectionOn("url-test", 2, 1))
	close(release[1])
	waitFor(t, "the new exit's IPv6 echo", func() bool { return s.v6Dials.Load() == 2 })
	time.Sleep(100 * time.Millisecond)
	if got := s.x.exitIPv6.Load(); got != exitIPv6Pending {
		t.Fatalf("state while only the old exit's echo has failed = %d, want pending", got)
	}
	close(release[2])
	waitFor(t, "the new exit's answer", func() bool { return s.x.exitIPv6.Load() == exitIPv6Absent })
}

// A group's first echo may go through a server its health check has not
// confirmed (mihomo's url-test starts on its first proxy, xray's balancer on its
// fallback), so the server the group then names is a new exit.
func TestSetServerSelection_TheFirstServerAGroupNamesAsksIPv6Again(t *testing.T) {
	s := newExitSession(t, 0, selectionOn("url-test", 2, -1))
	s.x.triggerIPResolve("link-up")
	waitFor(t, "the first IPv6 answer", func() bool { return s.x.exitIPv6.Load() == exitIPv6Absent })
	waitFor(t, "the IPEvent", func() bool { return len(s.events()) == 1 })

	s.x.setServerSelection(selectionOn("url-test", 2, 0))
	if got := s.x.exitIPv6.Load(); got != exitIPv6Pending {
		t.Fatalf("state right after the group named its server = %d, want pending", got)
	}
	waitFor(t, "the named server's IPv6 echo", func() bool { return s.v6Dials.Load() == 2 })
	waitFor(t, "the named server's answer", func() bool { return s.x.exitIPv6.Load() == exitIPv6Absent })
	time.Sleep(200 * time.Millisecond)
	if n := s.v6Dials.Load(); n != 2 {
		t.Fatalf("IPv6 echo dials = %d, want 2", n)
	}
}

// Naming a server of a one-server session is not a change of exit.
func TestSetServerSelection_TheSameServerNamedAgainKeepsTheAnswer(t *testing.T) {
	s := newExitSession(t, 0, selectionOn("", 1, 0))
	s.x.triggerIPResolve("link-up")
	waitFor(t, "the IPv6 answer", func() bool { return s.x.exitIPv6.Load() == exitIPv6Absent })
	s.x.noteExitSelection(mustJSON(t, selectionOn("", 1, 0)), selectionOn("", 1, 0))
	if got := s.x.exitIPv6.Load(); got != exitIPv6Absent {
		t.Fatalf("state = %d, want absent", got)
	}
}

func mustJSON(t *testing.T, sel *serverinfo.Selection) string {
	t.Helper()
	msg, err := sel.JSON()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// While the link is not up the exit's IPv6 echo that fails says nothing, and
// the session must not go on dropping IPv6 SYNs for it.
func TestEchoRound_AnIPv6FailureWhileTheLinkIsNotUpEndsThePending(t *testing.T) {
	s := newExitSession(t, 0, selectionOn("", 1, 0))
	s.x.linkState.Store(int32(liveness.StateUnknown))
	s.x.triggerIPResolve("server-change")
	waitFor(t, "the IPEvent", func() bool { return len(s.events()) == 1 })
	waitFor(t, "the end of the wait", func() bool { return s.x.exitIPv6.Load() == exitIPv6Unknown })
	if v := s.x.admitTCPFlow(netip.MustParseAddrPort("[2607:f8b0::1]:443")); v != tcpAdmit {
		t.Fatalf("verdict = %d, want admit", v)
	}
}

// Both families reset: the tunnel carries nothing, which says nothing about
// IPv6, so no IPv6 flow is refused.
func TestEchoRound_BothFamiliesFailingIsNotAnExitWithoutIPv6(t *testing.T) {
	s := newExitSession(t, 0, selectionOn("", 1, 0))
	s.v4Err = errors.New("dial tcp 203.0.113.7:443: connect: connection reset by peer")
	s.x.triggerIPResolve("link-up")
	waitFor(t, "the IPEvent", func() bool { return len(s.events()) == 1 })
	waitFor(t, "the end of the wait", func() bool { return s.x.exitIPv6.Load() == exitIPv6Unknown })
	if v := s.x.admitTCPFlow(netip.MustParseAddrPort("[2607:f8b0::1]:443")); v != tcpAdmit {
		t.Fatalf("verdict = %d, want admit", v)
	}
}

// No IPv6 is recorded when the round's IPv4 echo has reached its host, so the
// IPv6 failure that came first is held until then.
func TestEchoRound_NoIPv6IsRecordedOnceTheIPv4EchoGotThrough(t *testing.T) {
	s := newExitSession(t, 400*time.Millisecond, selectionOn("", 1, 0))
	s.x.triggerIPResolve("link-up")
	waitFor(t, "the IPv6 echo's failure", func() bool { return s.v6Dials.Load() == 1 })
	time.Sleep(100 * time.Millisecond)
	if got := s.x.exitIPv6.Load(); got != exitIPv6Pending {
		t.Fatalf("state while the IPv4 echo is out = %d, want pending", got)
	}
	waitFor(t, "the answer", func() bool { return s.x.exitIPv6.Load() == exitIPv6Absent })
}

// A link that never reports up leaves no echo to run; the wait has its own end.
func TestExitIPv6_PendingEndsAtItsDeadline(t *testing.T) {
	prev := exitIPv6PendingTimeout
	exitIPv6PendingTimeout = 50 * time.Millisecond
	t.Cleanup(func() { exitIPv6PendingTimeout = prev })

	s := newExitSession(t, 0, selectionOn("", 1, 0))
	if got := s.x.exitIPv6.Load(); got != exitIPv6Pending {
		t.Fatalf("state before the deadline = %d, want pending", got)
	}
	if v := s.x.admitTCPFlow(netip.MustParseAddrPort("[2607:f8b0::1]:443")); v != tcpDrop {
		t.Fatalf("verdict while pending = %d, want drop", v)
	}
	waitFor(t, "the deadline", func() bool { return s.x.exitIPv6.Load() == exitIPv6Unknown })
	if v := s.x.admitTCPFlow(netip.MustParseAddrPort("[2607:f8b0::1]:443")); v != tcpAdmit {
		t.Fatalf("verdict after the deadline = %d, want admit", v)
	}
}

// A deadline armed for an exit that has since answered, or been replaced, must
// not undo the answer.
func TestExitIPv6_TheDeadlineOfAnEarlierWaitLeavesALaterStateAlone(t *testing.T) {
	prev := exitIPv6PendingTimeout
	exitIPv6PendingTimeout = 100 * time.Millisecond
	t.Cleanup(func() { exitIPv6PendingTimeout = prev })

	s := newExitSession(t, 0, selectionOn("", 1, 0))
	s.x.triggerIPResolve("link-up")
	waitFor(t, "the IPv6 answer", func() bool { return s.x.exitIPv6.Load() == exitIPv6Absent })
	time.Sleep(250 * time.Millisecond)
	if got := s.x.exitIPv6.Load(); got != exitIPv6Absent {
		t.Fatalf("state after the first wait's deadline = %d, want absent", got)
	}
}

// The wait ends when the link is lost, since no echo will come through it.
func TestExitIPv6_PendingEndsWhenTheLinkIsLost(t *testing.T) {
	prev := quickLivenessInterval
	quickLivenessInterval = 10 * time.Millisecond
	t.Cleanup(func() { quickLivenessInterval = prev })

	s := newExitSession(t, 0, selectionOn("", 1, 0))
	s.x.startLiveness(livenessParams{
		engine:   "test",
		interval: time.Hour,
		probe: func(context.Context) (time.Duration, error) {
			return 0, errors.New("probe address unreachable")
		},
	})
	t.Cleanup(s.x.stopLiveness)
	waitFor(t, "the link to be reported down", func() bool { return s.x.linkState.Load() == int32(liveness.StateDown) })
	if got := s.x.exitIPv6.Load(); got != exitIPv6Unknown {
		t.Fatalf("state after the link was lost = %d, want unknown", got)
	}
}

// Groups that pick a server for each connection have no exit an echo speaks for.
func TestSetServerSelection_AGroupPickingPerConnectionIsNeverJudged(t *testing.T) {
	for _, strategy := range []string{"load-balance", "load-balance-hash", "random", "roundrobin"} {
		s := newExitSession(t, 0, selectionOn(strategy, 3, -1))
		if got := s.x.exitIPv6.Load(); got != exitIPv6Unknown {
			t.Fatalf("%s: state before the echo = %d, want unknown", strategy, got)
		}
		s.x.triggerIPResolve("link-up")
		waitFor(t, "the IPEvent", func() bool { return len(s.events()) == 1 })
		if got := s.x.exitIPv6.Load(); got != exitIPv6Unknown {
			t.Errorf("%s: state after the echo = %d, want unknown", strategy, got)
		}
		if v := s.x.admitTCPFlow(netip.MustParseAddrPort("[2607:f8b0::1]:443")); v != tcpAdmit {
			t.Errorf("%s: verdict = %d, want admit", strategy, v)
		}
		s.x.stopIPResolve()
	}
}

func TestStopIPResolve_ForgetsTheExit(t *testing.T) {
	s := newExitSession(t, 0, selectionOn("", 1, 0))
	s.x.triggerIPResolve("link-up")
	waitFor(t, "the IPv6 answer", func() bool { return s.x.exitIPv6.Load() == exitIPv6Absent })
	s.x.stopIPResolve()
	if got := s.x.exitIPv6.Load(); got != exitIPv6Unknown {
		t.Fatalf("state after a stop = %d, want unknown", got)
	}
}

var testDestination = netip.MustParseAddr("2607:f8b0::1")

const (
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10
)

// synPacket is an IPv6 TCP SYN from the TUN's client to destination.
func synPacket(destination netip.Addr) []byte {
	const tcpLength = 20
	source := netip.MustParseAddr("fdfe:dcba:9876::2")
	packet := make([]byte, 40+tcpLength)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:], tcpLength)
	packet[6], packet[7] = 6, 64
	copy(packet[8:], source.AsSlice())
	copy(packet[24:], destination.AsSlice())
	segment := packet[40:]
	binary.BigEndian.PutUint16(segment[0:], 40000)
	binary.BigEndian.PutUint16(segment[2:], 443)
	binary.BigEndian.PutUint32(segment[4:], 1000)
	segment[12] = 5 << 4
	segment[13] = tcpFlagSYN
	binary.BigEndian.PutUint16(segment[14:], 65535)
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
	}
	add(packet[8:40])
	sum += tcpLength + 6
	add(segment)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(segment[16:], ^uint16(sum))
	return packet
}

// synSession is a TUN stack on a test link: send injects the client's SYN and
// answer reads the TCP flags of the stack's reply, false when it sent none.
type synSession struct {
	send   func()
	answer func(wait time.Duration) (flags byte, answered bool)
}

// replyFlags is the TCP flags byte of a stack's IPv6 reply.
func replyFlags(t *testing.T, reply []byte) byte {
	t.Helper()
	if len(reply) < 54 {
		t.Fatalf("reply is %d bytes", len(reply))
	}
	return reply[40+13]
}

// checkStackJudgesByExit runs a TUN stack over an exit that has no IPv6, one
// that has it, and one that has yet to say. open builds the stack with the
// admission its production wiring gives it, for the controller it is handed.
func checkStackJudgesByExit(t *testing.T, open func(t *testing.T, x *CoreController) synSession) {
	t.Helper()
	armed := func(state int32) *CoreController {
		x := &CoreController{}
		x.exitIPv6.Store(state)
		return x
	}

	noIPv6 := open(t, armed(exitIPv6Absent))
	noIPv6.send()
	if flags, answered := noIPv6.answer(time.Second); !answered || flags&tcpFlagRST == 0 || flags&tcpFlagSYN != 0 {
		t.Errorf("an exit without IPv6: flags %#x (answered %v), want a reset and no SYN-ACK", flags, answered)
	}

	withIPv6 := open(t, armed(exitIPv6Carried))
	withIPv6.send()
	if flags, answered := withIPv6.answer(time.Second); !answered || flags&tcpFlagSYN == 0 || flags&tcpFlagACK == 0 {
		t.Errorf("an exit with IPv6: flags %#x (answered %v), want SYN+ACK", flags, answered)
	}

	pendingExit := armed(exitIPv6Pending)
	pending := open(t, pendingExit)
	pending.send()
	if flags, answered := pending.answer(300 * time.Millisecond); answered {
		t.Fatalf("before the echo answers: the SYN was answered with flags %#x, want silence", flags)
	}
	pendingExit.exitIPv6.Store(exitIPv6Carried)
	pending.send() // the client's retransmission
	if flags, answered := pending.answer(time.Second); !answered || flags&tcpFlagSYN == 0 || flags&tcpFlagACK == 0 {
		t.Errorf("the retransmitted SYN once the exit has IPv6: flags %#x (answered %v), want SYN+ACK", flags, answered)
	}
}
