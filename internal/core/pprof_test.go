package core

import "testing"

func TestPprofListenAddr_LoopbackOnly(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:6060", "localhost:6060", "[::1]:6060", "127.0.0.2:6060"} {
		if err := checkPprofListenAddr(addr); err != nil {
			t.Errorf("%q refused: %v", addr, err)
		}
	}
	for _, addr := range []string{":6060", "0.0.0.0:6060", "[::]:6060", "192.168.1.2:6060", "example.com:6060", "6060", "127.0.0.1"} {
		if err := checkPprofListenAddr(addr); err == nil {
			t.Errorf("%q accepted", addr)
		}
	}
}
