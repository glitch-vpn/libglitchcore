package linkrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"

	"github.com/glitch-vpn/libglitchcore/internal/pinger"
)

type fakeLink struct {
	info     Info
	dialed   chan string
	released atomic.Int32
}

// openFake starts a relay whose outbound dial runs dial, and closes it with the test.
func openFake(t *testing.T, req Request, dial func(ctx context.Context, addr string) (net.Conn, error)) *fakeLink {
	t.Helper()
	link := &fakeLink{dialed: make(chan string, 16)}
	dialer := &pinger.Dialer{
		Engine: "fake",
		Dial: func(ctx context.Context, _, addr string) (net.Conn, error) {
			link.dialed <- addr
			return dial(ctx, addr)
		},
		Release: func() { link.released.Add(1) },
	}
	info, err := start(dialer, req)
	if err != nil {
		t.Fatal(err)
	}
	link.info = info
	t.Cleanup(func() { Close(info.ID) })
	return link
}

func echoServer(t *testing.T) string {
	t.Helper()
	return serve(t, func(conn net.Conn) { _, _ = io.Copy(conn, conn) })
}

func serve(t *testing.T, handle func(conn net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				handle(conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func dialTo(target string) func(ctx context.Context, _ string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", target)
	}
}

// withoutHalfClose hides a connection's CloseWrite, as xray's connections have none.
type withoutHalfClose struct{ net.Conn }

func (l *fakeLink) address() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(l.info.Port))
}

func (l *fakeLink) socks(user, password string) (xproxy.Dialer, error) {
	return xproxy.SOCKS5("tcp", l.address(), &xproxy.Auth{User: user, Password: password}, xproxy.Direct)
}

func (l *fakeLink) rawClient(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", l.address(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func readN(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return buf
}

// loggedIn is a raw client past the method and login steps.
func (l *fakeLink) loggedIn(t *testing.T) net.Conn {
	t.Helper()
	conn := l.rawClient(t)
	_, _ = conn.Write([]byte{5, 1, 2})
	if got := readN(t, conn, 2); got[1] != 2 {
		t.Fatalf("method answer = %v", got)
	}
	login := []byte{1, byte(len(l.info.User))}
	login = append(login, l.info.User...)
	login = append(login, byte(len(l.info.Password)))
	login = append(login, l.info.Password...)
	_, _ = conn.Write(login)
	if got := readN(t, conn, 2); got[1] != 0 {
		t.Fatalf("login answer = %v", got)
	}
	return conn
}

// connectTo is a raw client's CONNECT to a name, answered with success.
func (l *fakeLink) connectTo(t *testing.T, host string, port int) net.Conn {
	t.Helper()
	conn := l.loggedIn(t)
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	request = append(request, byte(port>>8), byte(port))
	_, _ = conn.Write(request)
	if got := readN(t, conn, 10); got[1] != replySucceeded {
		t.Fatalf("CONNECT answer = %v", got)
	}
	return conn
}

func TestRelayCarriesAConnectionForAClientWithTheLogin(t *testing.T) {
	link := openFake(t, Request{}, dialTo(echoServer(t)))

	dialer, err := link.socks(link.info.User, link.info.Password)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", "named.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if got := readN(t, conn, 4); string(got) != "ping" {
		t.Errorf("echo = %q", got)
	}
	if got := <-link.dialed; got != "named.example:8443" {
		t.Errorf("the link dialled %q, want the name as the client sent it", got)
	}
}

func TestRelayAnswersARefusedClientBeforeItDialsAnything(t *testing.T) {
	link := openFake(t, Request{}, dialTo(echoServer(t)))

	t.Run("no login method offered", func(t *testing.T) {
		conn := link.rawClient(t)
		_, _ = conn.Write([]byte{5, 1, 0})
		if got := readN(t, conn, 2); got[1] != 0xFF {
			t.Errorf("answer = %v, want no acceptable method", got)
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		dialer, err := link.socks(link.info.User, "wrong")
		if err != nil {
			t.Fatal(err)
		}
		if conn, err := dialer.Dial("tcp", "named.example:80"); err == nil {
			conn.Close()
			t.Error("a client with the wrong password was carried")
		}
	})
	t.Run("a name that is not one", func(t *testing.T) {
		conn := link.loggedIn(t)
		_, _ = conn.Write([]byte{5, 1, 0, 3, 3, 'a', ' ', 'b', 0, 80})
		if got := readN(t, conn, 10); got[1] == 0 {
			t.Errorf("answer = %v, want a failure", got)
		}
	})
	t.Run("port zero", func(t *testing.T) {
		conn := link.loggedIn(t)
		_, _ = conn.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0})
		if got := readN(t, conn, 10); got[1] == 0 {
			t.Errorf("answer = %v, want a failure", got)
		}
	})

	select {
	case addr := <-link.dialed:
		t.Errorf("a refused client made the link dial %q", addr)
	default:
	}
}

func TestRelayRefusesEveryCommandButConnect(t *testing.T) {
	link := openFake(t, Request{}, dialTo(echoServer(t)))
	for name, command := range map[string]byte{"bind": 2, "udp associate": 3} {
		conn := link.loggedIn(t)
		_, _ = conn.Write([]byte{5, command, 0, 1, 127, 0, 0, 1, 0, 80})
		if got := readN(t, conn, 10); got[1] != replyCommandNotSupported {
			t.Errorf("%s: answer = %v, want command not supported", name, got)
		}
	}
}

func TestRelayAnswersAFailedDialWithoutTheEnginesText(t *testing.T) {
	failing := errors.New("vless://secret-uuid@server.example:443 refused")
	link := openFake(t, Request{TimeoutMs: 100}, func(ctx context.Context, addr string) (net.Conn, error) {
		if addr == "slow.example:80" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, failing
	})

	for addr, want := range map[string]byte{"down.example:80": replyGeneralFailure, "slow.example:80": replyHostUnreachable} {
		conn := link.loggedIn(t)
		host, port, _ := net.SplitHostPort(addr)
		portNumber, _ := strconv.Atoi(port)
		request := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
		request = append(request, byte(portNumber>>8), byte(portNumber))
		_, _ = conn.Write(request)
		got := readN(t, conn, 10)
		if got[1] != want {
			t.Errorf("%s: reply code = %d, want %d", addr, got[1], want)
		}
	}
}

func TestRelayCloseEndsLiveConnectionsAndReleasesTheLinkOnce(t *testing.T) {
	link := openFake(t, Request{}, dialTo(echoServer(t)))
	conn := link.connectTo(t, "named.example", 80)

	var closing sync.WaitGroup
	for range 3 {
		closing.Add(1)
		go func() {
			defer closing.Done()
			Close(link.info.ID)
			if n := link.released.Load(); n != 1 {
				t.Errorf("Close returned with the link released %d times, want 1", n)
			}
		}()
	}
	closing.Wait()

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Read(make([]byte, 1))
	var timeout net.Error
	if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
		t.Errorf("the connection survived the relay: %v", err)
	}
	if _, err := net.DialTimeout("tcp", link.address(), time.Second); err == nil {
		t.Error("the listener still accepts")
	}
	if n := link.released.Load(); n != 1 {
		t.Errorf("the link was released %d times, want 1", n)
	}
}

func shortTimers(t *testing.T) {
	t.Helper()
	previousIdle, previousLinger := idleUnit, lingerTimeout
	idleUnit, lingerTimeout = 50*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { idleUnit, lingerTimeout = previousIdle, previousLinger })
}

func waitReleased(link *fakeLink) bool {
	deadline := time.Now().Add(5 * time.Second)
	for link.released.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return link.released.Load() > 0
}

func TestRelayClosesItselfAfterItsLastConnectionEnds(t *testing.T) {
	shortTimers(t)
	link := openFake(t, Request{IdleSec: 10}, dialTo(echoServer(t)))
	held := link.connectTo(t, "named.example", 80)

	time.Sleep(3 * 10 * idleUnit)
	if n := link.released.Load(); n != 0 {
		t.Fatalf("the relay closed with a connection open (released %d)", n)
	}

	_ = held.Close()
	if !waitReleased(link) {
		t.Fatal("the relay stayed open after its last connection ended")
	}
	registryMu.Lock()
	_, listed := relays[link.info.ID]
	registryMu.Unlock()
	if listed {
		t.Error("the closed relay is still listed")
	}
}

func TestRelayClosesWhenNothingEverConnects(t *testing.T) {
	shortTimers(t)
	link := openFake(t, Request{IdleSec: 2}, dialTo(echoServer(t)))
	if !waitReleased(link) {
		t.Fatal("an unused relay stayed open")
	}
}

func TestRelayClosesAClientThatOutlivesItsServer(t *testing.T) {
	shortTimers(t)
	server := serve(t, func(conn net.Conn) { _, _ = conn.Write([]byte("done")) })
	link := openFake(t, Request{IdleSec: 2}, dialTo(server))
	conn := link.connectTo(t, "named.example", 80)

	if got := readN(t, conn, 4); string(got) != "done" {
		t.Fatalf("answer = %q", got)
	}
	// The client keeps its socket open. The relay counts as idle, and so
	// releases its link, only once it has ended the connection itself.
	if !waitReleased(link) {
		t.Fatal("a client that outlived its server kept the relay open")
	}
}

func TestRelayKeepsTheAnswerComingAfterAClientHalfClose(t *testing.T) {
	shortTimers(t)
	answerDelay := lingerTimeout / 3
	reply := func(conn net.Conn) {
		_, _ = io.ReadFull(conn, make([]byte, 3))
		time.Sleep(answerDelay)
		_, _ = conn.Write([]byte("answer"))
	}
	for name, wrap := range map[string]func(net.Conn) net.Conn{
		"a connection with a half-close": func(c net.Conn) net.Conn { return c },
		"a connection without":           func(c net.Conn) net.Conn { return withoutHalfClose{c} },
	} {
		t.Run(name, func(t *testing.T) {
			server := serve(t, reply)
			link := openFake(t, Request{IdleSec: 600}, func(ctx context.Context, _ string) (net.Conn, error) {
				conn, err := dialTo(server)(ctx, "")
				if err != nil {
					return nil, err
				}
				return wrap(conn), nil
			})
			conn := link.connectTo(t, "named.example", 80)
			_, _ = conn.Write([]byte("req"))
			_ = conn.(*net.TCPConn).CloseWrite()

			if got := readN(t, conn, 6); string(got) != "answer" {
				t.Errorf("answer = %q", got)
			}
		})
	}
}

func TestStartRefusesBeyondTheLimitAndReleasesTheLink(t *testing.T) {
	for range maxRelays {
		openFake(t, Request{}, dialTo(echoServer(t)))
	}
	var released atomic.Int32
	extra := &pinger.Dialer{Engine: "fake", Release: func() { released.Add(1) }}
	if _, err := start(extra, Request{}); !errors.Is(err, errTooManyRelays) {
		t.Fatalf("err = %v, want %v", err, errTooManyRelays)
	}
	if released.Load() != 1 {
		t.Errorf("the refused link was released %d times, want 1", released.Load())
	}
}

func TestEachRelayHasItsOwnPortAndLogin(t *testing.T) {
	seen := map[string]bool{}
	for range 4 {
		link := openFake(t, Request{}, dialTo(echoServer(t)))
		for _, value := range []string{link.info.ID, link.info.User, link.info.Password, strconv.Itoa(link.info.Port)} {
			if seen[value] {
				t.Errorf("%q was given to two relays", value)
			}
			seen[value] = true
		}
	}
}

func TestOpenRefusesWhatNoEngineCarries(t *testing.T) {
	for name, req := range map[string]Request{
		"empty":          {},
		"blank":          {Link: "  \n"},
		"unknown scheme": {Link: "nonsense://whatever"},
	} {
		if info, err := Open(req); err == nil {
			Close(info.ID)
			t.Errorf("%s: a relay was opened", name)
		}
	}
}
