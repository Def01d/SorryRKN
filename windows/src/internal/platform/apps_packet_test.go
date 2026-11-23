package platform

import (
	"encoding/binary"
	"testing"
)

func TestUDPSourcePort(t *testing.T) {
	ipv4 := make([]byte, 28)
	ipv4[0] = 0x45
	ipv4[9] = 17
	binary.BigEndian.PutUint16(ipv4[20:22], 54321)
	if port, is6, ok := udpSourcePort(ipv4); !ok || is6 || port != 54321 {
		t.Fatalf("ipv4 parse got (%d, %v, %v)", port, is6, ok)
	}

	ipv4Opts := make([]byte, 32)
	ipv4Opts[0] = 0x46
	ipv4Opts[9] = 17
	binary.BigEndian.PutUint16(ipv4Opts[24:26], 41234)
	if port, is6, ok := udpSourcePort(ipv4Opts); !ok || is6 || port != 41234 {
		t.Fatalf("ipv4 options parse got (%d, %v, %v)", port, is6, ok)
	}

	ipv6 := make([]byte, 48)
	ipv6[0] = 0x60
	ipv6[6] = 17
	binary.BigEndian.PutUint16(ipv6[40:42], 60001)
	if port, is6, ok := udpSourcePort(ipv6); !ok || !is6 || port != 60001 {
		t.Fatalf("ipv6 parse got (%d, %v, %v)", port, is6, ok)
	}

	// TCP or truncated packets must be rejected.
	ipv4[9] = 6
	if _, _, ok := udpSourcePort(ipv4); ok {
		t.Fatal("accepted TCP packet")
	}
	if _, _, ok := udpSourcePort([]byte{0x45, 0, 0}); ok {
		t.Fatal("accepted truncated packet")
	}
}
