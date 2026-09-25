package ipx

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

var (
	tunIP  = [4]byte{10, 255, 255, 1}
	peerIP = [4]byte{10, 8, 0, 2}
	remote = [4]byte{8, 8, 8, 8}
)

// ipv4 builds a valid IPv4 packet with correct header and L4 checksums.
func ipv4(proto byte, src, dst [4]byte, l4 []byte) []byte {
	pkt := make([]byte, 20+len(l4))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	copy(pkt[20:], l4)
	binary.BigEndian.PutUint16(pkt[10:12], Checksum(pkt[:20], 0))
	if off := l4SumOffset(proto); off >= 0 {
		binary.BigEndian.PutUint16(pkt[20+off:], 0)
		binary.BigEndian.PutUint16(pkt[20+off:], Checksum(pkt[20:], pseudoSum4(pkt, proto)))
	}
	return pkt
}

func l4SumOffset(proto byte) int {
	switch proto {
	case protoTCP:
		return 16
	case protoUDP:
		return 6
	case protoICMP:
		return 2
	}
	return -1
}

func pseudoSum4(pkt []byte, proto byte) uint32 {
	if proto == protoICMP {
		return 0
	}
	var acc uint32
	for i := 12; i < 20; i += 2 {
		acc += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	return acc + uint32(proto) + uint32(len(pkt)-20)
}

// verify4 checks that the header and L4 checksums of pkt are valid.
func verify4(t *testing.T, pkt []byte) {
	t.Helper()
	if Checksum(pkt[:20], 0) != 0 {
		t.Fatalf("bad IP header checksum")
	}
	proto := pkt[9]
	if l4SumOffset(proto) >= 0 && Checksum(pkt[20:], pseudoSum4(pkt, proto)) != 0 {
		t.Fatalf("bad L4 checksum (proto %d)", proto)
	}
}

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return b
}

func TestRewriteRoundTrip(t *testing.T) {
	for _, proto := range []byte{protoTCP, protoUDP, protoICMP} {
		for _, n := range []int{20, 21, 333} {
			pkt := ipv4(proto, tunIP, remote, payload(n))
			orig := append([]byte(nil), pkt...)

			if !RewriteSrc4(pkt, tunIP, peerIP) {
				t.Fatalf("proto %d: src not rewritten", proto)
			}
			if SrcIP(pkt).String() != "10.8.0.2" {
				t.Fatalf("proto %d: src = %s", proto, SrcIP(pkt))
			}
			verify4(t, pkt)

			// The reply comes back addressed to the peer IP.
			reply := ipv4(proto, remote, peerIP, payload(n))
			if !RewriteDst4(reply, peerIP, tunIP) {
				t.Fatalf("proto %d: dst not rewritten", proto)
			}
			verify4(t, reply)
			if DstIP(reply).String() != "10.255.255.1" {
				t.Fatalf("proto %d: dst = %s", proto, DstIP(reply))
			}

			RewriteSrc4(pkt, peerIP, tunIP)
			if string(pkt) != string(orig) {
				t.Fatalf("proto %d: round trip changed the packet", proto)
			}
		}
	}
}

func TestRewriteLeavesOtherAddresses(t *testing.T) {
	lan := [4]byte{192, 168, 1, 5}
	pkt := ipv4(protoTCP, lan, remote, payload(20))
	if RewriteSrc4(pkt, tunIP, peerIP) {
		t.Fatal("rewrote a packet whose source is not the tun IP")
	}
}

func TestRewriteUDPNoChecksum(t *testing.T) {
	pkt := ipv4(protoUDP, tunIP, remote, payload(12))
	binary.BigEndian.PutUint16(pkt[26:28], 0) // sender opted out
	RewriteSrc4(pkt, tunIP, peerIP)
	if binary.BigEndian.Uint16(pkt[26:28]) != 0 {
		t.Fatal("UDP zero checksum was modified")
	}
}

func TestRewriteICMPErrorInner(t *testing.T) {
	// A router reports "fragmentation needed" for a TCP segment we sent as peerIP.
	inner := ipv4(protoTCP, peerIP, remote, payload(20))[:28]
	icmp := append([]byte{3, 4, 0, 0, 0, 0, 0x05, 0x00}, inner...)
	pkt := ipv4(protoICMP, [4]byte{203, 0, 113, 1}, peerIP, icmp)

	if !RewriteDst4(pkt, peerIP, tunIP) {
		t.Fatal("not rewritten")
	}
	verify4(t, pkt)
	in := pkt[28:]
	if SrcIP(in).String() != "10.255.255.1" {
		t.Fatalf("inner src = %s", SrcIP(in))
	}
	if Checksum(in[:20], 0) != 0 {
		t.Fatal("bad inner header checksum")
	}
}

func TestRewriteNonFirstFragment(t *testing.T) {
	pkt := ipv4(protoTCP, tunIP, remote, payload(40))
	binary.BigEndian.PutUint16(pkt[6:8], 100) // fragment offset 800
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	binary.BigEndian.PutUint16(pkt[10:12], Checksum(pkt[:20], 0))
	body := append([]byte(nil), pkt[20:]...)

	RewriteSrc4(pkt, tunIP, peerIP)
	if Checksum(pkt[:20], 0) != 0 {
		t.Fatal("bad IP header checksum")
	}
	if string(pkt[20:]) != string(body) {
		t.Fatal("payload of a non-first fragment was modified")
	}
}

func TestReject4(t *testing.T) {
	pkt := ipv4(protoTCP, tunIP, remote, payload(40))
	r := Reject(pkt)
	if r == nil {
		t.Fatal("no reject")
	}
	verify4(t, r)
	if SrcIP(r).String() != "8.8.8.8" || DstIP(r).String() != "10.255.255.1" {
		t.Fatalf("reject %s -> %s", SrcIP(r), DstIP(r))
	}
	if r[20] != 3 || r[21] != 13 {
		t.Fatalf("type/code %d/%d", r[20], r[21])
	}
	if string(r[28:]) != string(pkt[:28]) {
		t.Fatal("quote is not the original header + 8 bytes")
	}

	// Never answer an ICMP error, but do answer an echo request.
	unreach := ipv4(protoICMP, tunIP, remote, append([]byte{3, 1, 0, 0, 0, 0, 0, 0}, pkt[:28]...))
	if Reject(unreach) != nil {
		t.Fatal("rejected an ICMP error")
	}
	if Reject(ipv4(protoICMP, tunIP, remote, []byte{8, 0, 0, 0, 0, 1, 0, 1})) == nil {
		t.Fatal("echo request not rejected")
	}
	if Reject(ipv4(protoUDP, tunIP, [4]byte{239, 1, 1, 1}, payload(8))) != nil {
		t.Fatal("rejected a multicast packet")
	}
}

func TestReject6(t *testing.T) {
	src := netip.MustParseAddr("fd00::1").As16()
	dst := netip.MustParseAddr("2001:db8::1").As16()
	pkt := make([]byte, 40+20)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], 20)
	pkt[6] = protoTCP
	pkt[7] = 64
	copy(pkt[8:24], src[:])
	copy(pkt[24:40], dst[:])

	r := Reject(pkt)
	if r == nil {
		t.Fatal("no reject")
	}
	if SrcIP(r).String() != "2001:db8::1" || DstIP(r).String() != "fd00::1" {
		t.Fatalf("reject %s -> %s", SrcIP(r), DstIP(r))
	}
	if Checksum(r[40:], pseudoSum6(r[8:40], len(r)-40, protoICMPv6)) != 0 {
		t.Fatal("bad ICMPv6 checksum")
	}

	mc := append([]byte(nil), pkt...)
	mc[24] = 0xff
	if Reject(mc) != nil {
		t.Fatal("rejected a multicast packet")
	}
}

// syn builds a TCP SYN (flags) with the given options and a valid checksum.
func syn(flags byte, opts []byte) []byte {
	l4 := make([]byte, 20+len(opts))
	binary.BigEndian.PutUint16(l4[0:], 40000)
	binary.BigEndian.PutUint16(l4[2:], 443)
	l4[12] = byte((20+len(opts))/4) << 4
	l4[13] = flags
	copy(l4[20:], opts)
	return ipv4(protoTCP, tunIP, remote, l4)
}

func mssOf(pkt []byte) uint16 {
	opts := pkt[40 : 20+int(pkt[32]>>4)*4]
	for i := 0; i+3 < len(opts); {
		if opts[i] == 1 {
			i++
			continue
		}
		if opts[i] == 2 {
			return binary.BigEndian.Uint16(opts[i+2:])
		}
		i += int(opts[i+1])
	}
	return 0
}

func TestClampMSS(t *testing.T) {
	linuxSYN := []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7} // mss 1460, sackOK, TS, wscale
	nopFirst := []byte{1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 2, 4, 0x05, 0x84}             // TS before mss 1412
	for name, pkt := range map[string][]byte{
		"syn":            syn(0x02, linuxSYN),
		"syn-ack":        syn(0x12, linuxSYN),
		"mss after opts": syn(0x02, nopFirst),
	} {
		if !ClampMSS(pkt, 1280) {
			t.Fatalf("%s: not clamped", name)
		}
		verify4(t, pkt)
		if got := mssOf(pkt); got != 1280 {
			t.Fatalf("%s: mss %d, want 1280", name, got)
		}
	}

	small := syn(0x02, []byte{2, 4, 0x04, 0x00}) // mss 1024
	if ClampMSS(small, 1280) || mssOf(small) != 1024 {
		t.Fatal("a smaller MSS was changed")
	}
	ack := syn(0x10, linuxSYN) // not a SYN
	if ClampMSS(ack, 1280) {
		t.Fatal("a non-SYN segment was changed")
	}
	bad := syn(0x02, []byte{2, 9, 0x05, 0xb4}) // option length beyond the header
	if ClampMSS(bad, 1280) {
		t.Fatal("a malformed option list was changed")
	}
}
