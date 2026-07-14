package procname

import (
	"net/netip"
	"testing"
)

func TestParseProcAddr(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"0100007F", "127.0.0.1"},
		{"0200000A", "10.0.0.2"},
		{"00000000000000000000000001000000", "::1"},
		{"00000000000000000000000000000000", "::"},
	}
	for _, c := range cases {
		got, ok := parseProcAddr(c.in)
		if !ok || got != netip.MustParseAddr(c.want) {
			t.Errorf("parseProcAddr(%q) = (%v, %v), want %s", c.in, got, ok, c.want)
		}
	}
	if _, ok := parseProcAddr("zz"); ok {
		t.Error("parsed invalid hex")
	}
}

const sampleProcNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0200000A:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000000000000000 100 0 0 10 0`

func TestFindSocketInode(t *testing.T) {
	if got := findSocketInode(sampleProcNetTCP, netip.MustParseAddr("10.0.0.2"), 8080); got != 67890 {
		t.Errorf("inode = %d, want 67890", got)
	}
	// 0.0.0.0-bound row matches any src.
	if got := findSocketInode(sampleProcNetTCP, netip.MustParseAddr("127.0.0.1"), 631); got != 12345 {
		t.Errorf("inode = %d, want 12345", got)
	}
	if got := findSocketInode(sampleProcNetTCP, netip.MustParseAddr("10.0.0.3"), 8080); got != 0 {
		t.Errorf("inode = %d, want 0 (addr mismatch)", got)
	}
}
