package platform

import "encoding/binary"

// udpSourcePort extracts the source UDP port from a raw IPv4 or IPv6 packet
// as captured on a WinDivert network layer handle.
func udpSourcePort(raw []byte) (port uint16, ipv6 bool, ok bool) {
	if len(raw) < 20 {
		return 0, false, false
	}
	switch raw[0] >> 4 {
	case 4:
		ihl := int(raw[0]&0x0f) * 4
		if ihl < 20 || raw[9] != 17 || len(raw) < ihl+8 {
			return 0, false, false
		}
		return binary.BigEndian.Uint16(raw[ihl : ihl+2]), false, true
	case 6:
		if len(raw) < 48 || raw[6] != 17 {
			return 0, false, false
		}
		return binary.BigEndian.Uint16(raw[40:42]), true, true
	default:
		return 0, false, false
	}
}
