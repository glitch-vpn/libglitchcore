package loopbackport

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
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

func TestAddressInUse_NamesALostBindWhateverLanguageItsMessageIsIn(t *testing.T) {
	held, err := net.Listen("tcp", net.JoinHostPort(Address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	_, err = net.Listen("tcp", held.Addr().String())
	if !AddressInUse(err) {
		t.Errorf("a second listener on %s: AddressInUse(%v) = false", held.Addr(), err)
	}
	for _, errno := range []syscall.Errno{syscall.EADDRINUSE, windowsAddressInUse} {
		if !AddressInUse(fmt.Errorf("\u0441\u043b\u0443\u0448\u0430\u0442\u044c: %w", errno)) {
			t.Errorf("AddressInUse of errno %d under another language's text = false", errno)
		}
	}
	if AddressInUse(nil) || AddressInUse(errors.New("address already in use")) || AddressInUse(syscall.ECONNREFUSED) {
		t.Error("AddressInUse is true for what is not a lost bind")
	}
}

func TestRetry_PicksAnotherPortOnlyForALostBind(t *testing.T) {
	var ports []int
	port, err := Retry(func(port int) error {
		ports = append(ports, port)
		if len(ports) < 3 {
			return fmt.Errorf("bind: %w", windowsAddressInUse)
		}
		return nil
	})
	if err != nil || len(ports) != 3 || port != ports[2] || ports[0] == ports[1] || ports[1] == ports[2] {
		t.Fatalf("Retry = %d, %v after ports %v, want the third, a new one each time", port, err, ports)
	}

	refused := errors.New("config refused")
	calls := 0
	if _, err := Retry(func(int) error { calls++; return refused }); err != refused || calls != 1 {
		t.Fatalf("Retry for another error = %v after %d calls, want it returned after one", err, calls)
	}

	calls = 0
	if _, err := Retry(func(int) error { calls++; return syscall.EADDRINUSE }); !AddressInUse(err) || calls != 8 {
		t.Fatalf("Retry for a port that is always lost = %v after %d calls, want the last lost bind after 8", err, calls)
	}
}
