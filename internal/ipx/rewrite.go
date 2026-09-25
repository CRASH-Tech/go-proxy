package ipx

import "encoding/binary"

const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// RewriteSrc4 replaces the source address of an IPv4 packet in place when it
// equals from, fixing the IP and TCP/UDP checksums. For an ICMP error the
// embedded original packet's destination is rewritten too, so the error still
// matches the flow it refers to. Reports whether the packet was changed.
func RewriteSrc4(pkt []byte, from, to [4]byte) bool {
	return rewrite4(pkt, 12, from, to)
}

// RewriteDst4 is RewriteSrc4 for the destination address (and the embedded
// packet's source in an ICMP error).
func RewriteDst4(pkt []byte, from, to [4]byte) bool {
	return rewrite4(pkt, 16, from, to)
}

// rewrite4 swaps the address at off (12 = src, 16 = dst) for to if it is from.
func rewrite4(pkt []byte, off int, from, to [4]byte) bool {
	ihl, ok := header4(pkt)
	if !ok || [4]byte(pkt[off:off+4]) != from {
		return false
	}
	setAddr(pkt, off, 10, to)

	// Only the first fragment carries the L4 header; its checksum covers the
	// whole datagram, so adjusting it there is enough.
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return true
	}
	l4 := pkt[ihl:]
	switch pkt[9] {
	case protoTCP:
		if len(l4) >= 18 {
			fixSum(l4[16:18], from, to, false)
		}
	case protoUDP:
		if len(l4) >= 8 {
			fixSum(l4[6:8], from, to, true)
		}
	case protoICMP:
		// The embedded packet travelled the other way: its opposite address is ours.
		if len(l4) >= 8 && isICMPError4(l4[0]) {
			if inner := l4[8:]; len(inner) >= 20 {
				if _, ok := header4(inner); ok && [4]byte(inner[28-off:32-off]) == from {
					setAddr(inner, 28-off, 10, to)
					binary.BigEndian.PutUint16(l4[2:4], 0)
					binary.BigEndian.PutUint16(l4[2:4], Checksum(l4, 0))
				}
			}
		}
	}
	return true
}

// header4 validates an IPv4 header and returns its length.
func header4(pkt []byte) (int, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return 0, false
	}
	return ihl, true
}

// setAddr writes addr at off and patches the header checksum at sumOff.
func setAddr(pkt []byte, off, sumOff int, addr [4]byte) {
	old := [4]byte(pkt[off : off+4])
	copy(pkt[off:off+4], addr[:])
	fixSum(pkt[sumOff:sumOff+2], old, addr, false)
}

// fixSum incrementally updates the checksum in sum after the address old was
// replaced by new in the covered data.
func fixSum(sum []byte, old, new [4]byte, udp bool) {
	AdjustChecksum(sum, old[:], new[:], udp)
}

// AdjustChecksum incrementally updates the checksum in sum (2 bytes) after the
// even-length field old was replaced by new in the covered data (RFC 1624).
// udp keeps the "no checksum" value 0 and never produces it.
func AdjustChecksum(sum, old, new []byte, udp bool) {
	cur := binary.BigEndian.Uint16(sum)
	if udp && cur == 0 {
		return
	}
	acc := uint32(^cur)
	for i := 0; i+1 < len(old); i += 2 {
		acc += uint32(^binary.BigEndian.Uint16(old[i:]))
		acc += uint32(binary.BigEndian.Uint16(new[i:]))
	}
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	res := ^uint16(acc)
	if udp && res == 0 {
		res = 0xffff
	}
	binary.BigEndian.PutUint16(sum, res)
}

// Checksum returns the Internet checksum of b, starting from the partial sum
// initial (e.g. a pseudo-header sum).
func Checksum(b []byte, initial uint32) uint16 {
	acc := initial
	for len(b) >= 2 {
		acc += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		acc += uint32(b[0]) << 8
	}
	for acc>>16 != 0 {
		acc = acc&0xffff + acc>>16
	}
	return ^uint16(acc)
}

// isICMPError4 reports whether an ICMPv4 type is an error message (which
// embeds the offending packet and must never be answered with another error).
func isICMPError4(typ byte) bool {
	switch typ {
	case 3, 4, 5, 11, 12:
		return true
	}
	return false
}

// IsICMPv4Error reports whether pkt is an IPv4 ICMP error message.
func IsICMPv4Error(pkt []byte) bool {
	ihl, ok := header4(pkt)
	return ok && pkt[9] == protoICMP && len(pkt) > ihl && isICMPError4(pkt[ihl])
}

// ClampMSS lowers the MSS option of an IPv4 TCP SYN (or SYN-ACK) to mss when it
// is larger, fixing the TCP checksum, so the endpoints never send segments that
// do not fit the tunnel -- without relying on path-MTU discovery, whose ICMP is
// often filtered or ignored. It reports whether the packet was changed.
func ClampMSS(pkt []byte, mss uint16) bool {
	ihl, ok := header4(pkt)
	if !ok || pkt[9] != protoTCP || binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return false
	}
	tcp := pkt[ihl:]
	if len(tcp) < 20 || tcp[13]&0x02 == 0 { // not a SYN
		return false
	}
	doff := int(tcp[12]>>4) * 4
	if doff < 20 || len(tcp) < doff {
		return false
	}
	opts := tcp[20:doff]
	for i := 0; i < len(opts); {
		switch kind := opts[i]; kind {
		case 0: // end of options
			return false
		case 1: // no-op
			i++
			continue
		}
		if i+1 >= len(opts) || opts[i+1] < 2 || i+int(opts[i+1]) > len(opts) {
			return false
		}
		if opts[i] == 2 && opts[i+1] == 4 { // MSS
			field := opts[i+2 : i+4]
			if binary.BigEndian.Uint16(field) <= mss {
				return false
			}
			var old, new [2]byte
			copy(old[:], field)
			binary.BigEndian.PutUint16(new[:], mss)
			copy(field, new[:])
			AdjustChecksum(tcp[16:18], old[:], new[:], false)
			return true
		}
		i += int(opts[i+1])
	}
	return false
}
