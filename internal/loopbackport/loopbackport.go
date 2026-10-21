// Package loopbackport picks the 127.0.0.1 ports the tests start engines and
// their upstream servers on: a proxy-mode inbound listens on TCP and UDP both.
// It imports no engine.
package loopbackport

import (
	"errors"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"sync"
)

// Address is where every port Pick returns was found free.
const Address = "127.0.0.1"

// The OS's own port 0 is asked first: it never hands out a port another
// process listens on, while a bind to 127.0.0.1 succeeds on Windows over
// another process's 0.0.0.0 listener and would take its loopback clients.
// When the UDP twin of that port is taken, candidates are drawn at random
// instead: Windows hands out port 0 in sequence, and Hyper-V and WinNAT
// exclude UDP ports in blocks of hundreds, so asking port 0 again walks the
// block one port at a time. Random draws are independent, and each fails only
// as often as the excluded and busy ports cover the range.
const (
	firstCandidate = 49152
	lastCandidate  = 65535
	attempts       = 256
)

// A test picks several ports and binds none of them until its engines start,
// so a port is not handed out again while it is likely still unbound.
var (
	recentMu sync.Mutex
	recent   []int
)

const recentKept = 16

// Pick returns a port bindable on both TCP and UDP. Nothing holds it once Pick
// returns.
func Pick() (int, error) {
	if port, ok := fromPortZero(); ok && claim(port) {
		return port, nil
	}
	for range attempts {
		port := firstCandidate + rand.IntN(lastCandidate-firstCandidate+1)
		if bindable(port) && claim(port) {
			return port, nil
		}
	}
	return 0, errors.New("no loopback port free on both TCP and UDP")
}

func fromPortZero() (int, bool) {
	l, err := net.Listen("tcp", net.JoinHostPort(Address, "0"))
	if err != nil {
		return 0, false
	}
	port := l.Addr().(*net.TCPAddr).Port
	defer l.Close()
	u, err := net.ListenPacket("udp", net.JoinHostPort(Address, strconv.Itoa(port)))
	if err != nil {
		return 0, false
	}
	_ = u.Close()
	return port, true
}

func bindable(port int) bool {
	addr := net.JoinHostPort(Address, strconv.Itoa(port))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	defer l.Close()
	u, err := net.ListenPacket("udp", addr)
	if err != nil {
		return false
	}
	_ = u.Close()
	return true
}

func claim(port int) bool {
	recentMu.Lock()
	defer recentMu.Unlock()
	if slices.Contains(recent, port) {
		return false
	}
	recent = append(recent, port)
	if len(recent) > recentKept {
		recent = recent[1:]
	}
	return true
}
