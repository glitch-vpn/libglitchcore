package loopbackport

import (
	"net"
	"strconv"
	"testing"
)

// Holding UDP on the ports the OS hands out next as TCP's port 0 is what a
// WinNAT exclusion block does on Windows, where port 0 comes in sequence; the
// block here is as wide as the widest one seen on a developer machine.
func TestPick_SurvivesAUDPBlockAheadOfPortZero(t *testing.T) {
	const blockWidth = 600
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	next := l.Addr().(*net.TCPAddr).Port + 1
	_ = l.Close()
	for port := next; port < next+blockWidth && port <= 65535; port++ {
		u, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			continue // excluded or busy already: blocked all the same
		}
		t.Cleanup(func() { _ = u.Close() })
	}

	seen := map[int]bool{}
	for range recentKept {
		port, err := Pick()
		if err != nil {
			t.Fatalf("Pick: %v", err)
		}
		if !bindable(port) {
			t.Fatalf("Pick returned %d, which is not free on both TCP and UDP", port)
		}
		if seen[port] {
			t.Fatalf("Pick returned %d twice in a row of %d", port, recentKept)
		}
		seen[port] = true
	}
}
