package core

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
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
