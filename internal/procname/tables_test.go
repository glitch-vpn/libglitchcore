package procname

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func tcp4Row(pid uint32, addr [4]byte, port uint16) []byte {
	row := make([]byte, tcp4Layout.rowLen)
	binary.LittleEndian.PutUint32(row[0:], 5) // MIB_TCP_STATE_ESTAB
	copy(row[4:], addr[:])
	binary.BigEndian.PutUint16(row[8:], port)
	binary.LittleEndian.PutUint32(row[20:], pid)
	return row
}

func udp4Row(pid uint32, addr [4]byte, port uint16) []byte {
	row := make([]byte, udp4Layout.rowLen)
	copy(row[0:], addr[:])
	binary.BigEndian.PutUint16(row[4:], port)
	binary.LittleEndian.PutUint32(row[8:], pid)
	return row
}

func tcp6Row(pid uint32, addr [16]byte, port uint16) []byte {
	row := make([]byte, tcp6Layout.rowLen)
	copy(row[0:], addr[:])
	binary.BigEndian.PutUint16(row[20:], port)
	binary.LittleEndian.PutUint32(row[52:], pid)
	return row
}

func table(rows ...[]byte) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(len(rows)))
	for _, r := range rows {
		buf = append(buf, r...)
	}
	return buf
}

func TestMatchPid_TCP4PicksExactAddr(t *testing.T) {
	tbl := table(
		tcp4Row(111, [4]byte{10, 0, 0, 1}, 5000),
		tcp4Row(222, [4]byte{10, 0, 0, 2}, 5000),
		tcp4Row(333, [4]byte{10, 0, 0, 2}, 5001),
	)
	pid, ok := matchPid(tbl, tcp4Layout, netip.MustParseAddr("10.0.0.2"), 5000)
	if !ok || pid != 222 {
		t.Fatalf("matchPid = (%d, %v), want (222, true)", pid, ok)
	}
}

func TestMatchPid_UDP4Wildcard(t *testing.T) {
	tbl := table(udp4Row(777, [4]byte{0, 0, 0, 0}, 53))
	pid, ok := matchPid(tbl, udp4Layout, netip.MustParseAddr("192.168.1.5"), 53)
	if !ok || pid != 777 {
		t.Fatalf("matchPid = (%d, %v), want (777, true)", pid, ok)
	}
}

func TestMatchPid_TCP6(t *testing.T) {
	var addr [16]byte
	addr[15] = 1 // ::1
	tbl := table(tcp6Row(444, addr, 8080))
	pid, ok := matchPid(tbl, tcp6Layout, netip.MustParseAddr("::1"), 8080)
	if !ok || pid != 444 {
		t.Fatalf("matchPid = (%d, %v), want (444, true)", pid, ok)
	}
}

func TestMatchPid_NoMatchAndTruncated(t *testing.T) {
	tbl := table(tcp4Row(1, [4]byte{127, 0, 0, 1}, 80))
	if _, ok := matchPid(tbl, tcp4Layout, netip.MustParseAddr("127.0.0.1"), 81); ok {
		t.Error("matched wrong port")
	}
	// Row count larger than the buffer must not panic.
	short := table(tcp4Row(1, [4]byte{127, 0, 0, 1}, 80))
	binary.LittleEndian.PutUint32(short, 99)
	if _, ok := matchPid(short, tcp4Layout, netip.MustParseAddr("1.2.3.4"), 9); ok {
		t.Error("matched in truncated table")
	}
	if _, ok := matchPid(nil, tcp4Layout, netip.MustParseAddr("1.2.3.4"), 9); ok {
		t.Error("matched in empty table")
	}
}
