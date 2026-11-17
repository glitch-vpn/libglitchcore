//go:build !no_mihomo

package core

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	mihomoLog "github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"

	"github.com/glitch-vpn/libglitchcore/internal/dnsconfig"
)

// mihomo keeps cache.db open inside its home dir, so the dir outlives the test.
func mihomoTestHome(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "glitch-mihomo-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureMihomoHome(dir); err != nil {
		t.Fatal(err)
	}
}

// recordingResolver answers nothing and reports each name it is asked.
func recordingResolver(t *testing.T) (addr string, asked <-chan string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	names := make(chan string, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q D.Msg
			if q.Unpack(buf[:n]) == nil && len(q.Question) > 0 {
				names <- strings.TrimSuffix(q.Question[0].Name, ".")
			}
		}
	}()
	return pc.LocalAddr().String(), names
}

func drain(c <-chan string) {
	for len(c) > 0 {
		<-c
	}
}

// listenDirect reports each connection to host:port as "direct:<host>" on
// seen, when given, and hands it to serve, or drains it when serve is nil.
func listenDirect(t *testing.T, host net.IP, port int, seen chan<- string, serve func(net.Conn)) {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host.String(), fmt.Sprint(port)))
	if err != nil {
		t.Skipf("listen on %s:%d: %v", host, port, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if serve == nil {
		serve = func(c net.Conn) {
			buf := make([]byte, 512)
			for {
				if _, err := c.Read(buf); err != nil {
					return
				}
			}
		}
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if seen != nil {
				seen <- "direct:" + host.String()
			}
			go func() {
				defer c.Close()
				serve(c)
			}()
		}
	}()
}

// requireQueryTravels waits for the first resolver reached and then, for a
// second, lets the engine retry it, failing on any other destination.
func requireQueryTravels(t *testing.T, proxied, fromDevice <-chan string, want string) {
	t.Helper()
	deadline := time.After(15 * time.Second)
	for first := true; ; first = false {
		var seen string
		select {
		case seen = <-proxied:
		case seen = <-fromDevice:
		case <-deadline:
			if first {
				t.Fatal("the query reached neither the proxy nor a resolver")
			}
			return
		}
		if seen != want {
			t.Fatalf("a query reached %s, want %s", seen, want)
		}
		if first {
			deadline = time.After(time.Second)
		}
	}
}

var normalMode = dnsconfig.Config{Mode: dnsconfig.ModeNormal}

// fakeIPFor asks mihomo's resolver for name, which allocates its fake-ip.
func fakeIPFor(t *testing.T, name string) net.IP {
	t.Helper()
	q := new(D.Msg)
	q.SetQuestion(name+".", D.TypeA)
	packed, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out, err := resolver.RelayDnsPacket(context.Background(), packed, make([]byte, 4096))
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	var answer D.Msg
	if err := answer.Unpack(out); err != nil || len(answer.Answer) == 0 {
		t.Fatalf("resolve %s: %v, %v", name, answer.Answer, err)
	}
	return answer.Answer[0].(*D.A).A
}

// What mihomo did with a flow: "proxy:<destination>" as the recorder behind
// the proxy saw it, "direct:<address>" as the listener at that address saw it,
// "block" as mihomo's routing line for a refused flow says.
func flowOutcome(t *testing.T, remote string, port int, proxied, direct <-chan string, routed <-chan mihomoLog.Event) string {
	t.Helper()
	addr := net.JoinHostPort(remote, fmt.Sprint(port))
	deadline := time.After(10 * time.Second)
	for {
		select {
		case s := <-proxied:
			return s
		case s := <-direct:
			return s
		case ev := <-routed:
			if strings.Contains(ev.Payload, addr) && strings.Contains(ev.Payload, "REJECT") {
				return "block"
			}
		case <-deadline:
			return "none"
		}
	}
}
