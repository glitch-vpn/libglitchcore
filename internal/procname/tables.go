package procname

import (
	"encoding/binary"
	"net/netip"
)

// iphlpapi MIB_*ROW_OWNER_PID byte offsets. Kept OS-neutral so the parsing is
// unit-testable off Windows. Ports sit in the low word of a DWORD in network
// byte order; addresses are raw octets.
type tableLayout struct {
	rowLen, addrOff, addrLen, portOff, pidOff int
}

var (
	tcp4Layout = tableLayout{24, 4, 4, 8, 20}
	tcp6Layout = tableLayout{56, 0, 16, 20, 52}
	udp4Layout = tableLayout{12, 0, 4, 4, 8}
	udp6Layout = tableLayout{28, 0, 16, 20, 24}
)

func layoutFor(tcp, v6 bool) tableLayout {
	switch {
	case tcp && v6:
		return tcp6Layout
	case tcp:
		return tcp4Layout
	case v6:
		return udp6Layout
	default:
		return udp4Layout
	}
}

// matchPid scans a MIB_*TABLE_OWNER_PID buffer (DWORD row count, then rows).
// Wildcard-bound rows match any src - UDP sockets rarely bind an address.
func matchPid(table []byte, l tableLayout, src netip.Addr, port uint16) (uint32, bool) {
	if len(table) < 4 {
		return 0, false
	}
	n := int(binary.LittleEndian.Uint32(table))
	rows := table[4:]
	for r := 0; r < n && (r+1)*l.rowLen <= len(rows); r++ {
		row := rows[r*l.rowLen : (r+1)*l.rowLen]
		if binary.BigEndian.Uint16(row[l.portOff:l.portOff+2]) != port {
			continue
		}
		var addr netip.Addr
		if l.addrLen == 4 {
			addr = netip.AddrFrom4([4]byte(row[l.addrOff : l.addrOff+4]))
		} else {
			addr = netip.AddrFrom16([16]byte(row[l.addrOff : l.addrOff+16])).Unmap()
		}
		if addr == src || addr.IsUnspecified() {
			return binary.LittleEndian.Uint32(row[l.pidOff : l.pidOff+4]), true
		}
	}
	return 0, false
}
