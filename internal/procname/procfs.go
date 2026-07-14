package procname

import (
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
)

// /proc/net addresses are hex with bytes swapped per 32-bit group (the kernel
// prints s6_addr32 words in host order, little-endian on our targets).
func parseProcAddr(s string) (netip.Addr, bool) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return netip.Addr{}, false
	}
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}), true
	case 16:
		var a [16]byte
		for g := 0; g < 4; g++ {
			for k := 0; k < 4; k++ {
				a[g*4+k] = b[g*4+3-k]
			}
		}
		return netip.AddrFrom16(a).Unmap(), true
	}
	return netip.Addr{}, false
}

// findSocketInode scans /proc/net/{tcp,udp}{,6} content ("sl local_address
// rem_address st ... uid timeout inode ...") for the socket bound to src:port.
func findSocketInode(procNet string, src netip.Addr, port uint16) uint64 {
	for _, line := range strings.Split(procNet, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		i := strings.LastIndexByte(f[1], ':')
		if i < 0 {
			continue
		}
		p, err := strconv.ParseUint(f[1][i+1:], 16, 16)
		if err != nil || uint16(p) != port {
			continue
		}
		addr, ok := parseProcAddr(f[1][:i])
		if !ok || (addr != src && !addr.IsUnspecified()) {
			continue
		}
		if inode, err := strconv.ParseUint(f[9], 10, 64); err == nil && inode != 0 {
			return inode
		}
	}
	return 0
}
