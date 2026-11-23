//go:build !no_xray

package core

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// relayingSocks is a SOCKS5 server with no login that carries each CONNECT to
// its destination, so a link to it is an exit that works.
func relayingSocks(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go relaySocksConnect(client)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func relaySocksConnect(client net.Conn) {
	defer client.Close()
	head := make([]byte, 262)
	if _, err := io.ReadFull(client, head[:2]); err != nil {
		return
	}
	_, _ = io.ReadFull(client, head[:head[1]])
	_, _ = client.Write([]byte{5, 0})
	if _, err := io.ReadFull(client, head[:4]); err != nil {
		return
	}
	var host string
	switch head[3] {
	case 1:
		_, _ = io.ReadFull(client, head[:4])
		host = net.IP(head[:4]).String()
	case 3:
		_, _ = io.ReadFull(client, head[:1])
		length := int(head[0])
		_, _ = io.ReadFull(client, head[:length])
		host = string(head[:length])
	default:
		return
	}
	_, _ = io.ReadFull(client, head[:2])
	port := binary.BigEndian.Uint16(head[:2])
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))), 5*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	_, _ = client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// A session that has no way to fetch its exit's IP when liveness first calls
// the link up gets no IPEvent at all: the link-up is the only trigger. The
// start is held where it takes the lock the arming takes, so liveness, if it
// has already begun, finishes its first probe before the arming happens.
func TestXrayStart_ArmsTheIPEchoBeforeLivenessCanCallTheLinkUp(t *testing.T) {
	x := &CoreController{}
	t.Cleanup(func() {
		x.stopStats()
		x.coreMutex.Lock()
		defer x.coreMutex.Unlock()
		x.endSessionLoops()
		x.xrayStopLocked()
	})
	events := collectEvents(t, IPEvent)

	var probes atomic.Int32
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(probe.Close)
	echo := echoServer(t, "198.51.100.9")

	request, _ := xrayProxyStart(t)
	request.Config = "socks://127.0.0.1:" + strconv.Itoa(relayingSocks(t)) + "#exit"
	request.Opts["resolveExternalIp"] = "1"
	request.Opts["probeUrl"] = probe.URL
	request.Opts["ipv4EchoUrl"] = echo.URL
	request.Opts["disableIPv6"] = "1"

	x.ipFetchMu.Lock()
	started := make(chan int32, 1)
	go func() { started <- x.HandleXrayStart(request) }()
	for deadline := time.Now().Add(time.Second); probes.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	x.ipFetchMu.Unlock()

	if result := <-started; result != glitchCoreResultSuccess {
		t.Fatalf("xray start = %d", result)
	}
	waitFor(t, "the IPEvent", func() bool { return len(events()) > 0 })
	var state externalIPState
	if err := json.Unmarshal([]byte(events()[0]), &state); err != nil {
		t.Fatal(err)
	}
	if state.IPv4 != "198.51.100.9" {
		t.Fatalf("IPEvent = %+v, want the echo's address", state)
	}
}
