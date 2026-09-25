package ipx

import "encoding/binary"

// Reject builds the ICMP "communication administratively prohibited" error for
// a packet that is not allowed anywhere, so the sender fails fast instead of
// timing out. It returns nil when no error may be sent (RFC 1122 / RFC 4443:
// never in reply to an ICMP error, a non-first fragment or a multicast).
func Reject(pkt []byte) []byte {
	switch Version(pkt) {
	case 4:
		return reject4(pkt)
	case 6:
		return reject6(pkt)
	}
	return nil
}

func reject4(pkt []byte) []byte {
	ihl, ok := header4(pkt)
	if !ok {
		return nil
	}
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 || pkt[16]>>4 == 0xe || pkt[16] == 0xff {
		return nil
	}
	if pkt[9] == protoICMP && (len(pkt) < ihl+1 || isICMPError4(pkt[ihl])) {
		return nil
	}
	// Original IP header + first 8 bytes of its payload (enough for ports).
	quote := pkt[:min(len(pkt), ihl+8)]

	out := make([]byte, 20+8+len(quote))
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[8] = 64
	out[9] = protoICMP
	copy(out[12:16], pkt[16:20]) // from the unreachable destination
	copy(out[16:20], pkt[12:16])
	binary.BigEndian.PutUint16(out[10:12], Checksum(out[:20], 0))

	icmp := out[20:]
	icmp[0], icmp[1] = 3, 13 // destination unreachable, administratively prohibited
	copy(icmp[8:], quote)
	binary.BigEndian.PutUint16(icmp[2:4], Checksum(icmp, 0))
	return out
}

func reject6(pkt []byte) []byte {
	if len(pkt) < 40 || pkt[24] == 0xff { // multicast destination
		return nil
	}
	if pkt[6] == protoICMPv6 && (len(pkt) < 41 || pkt[40] < 128) { // error message
		return nil
	}
	// As much of the original as fits in the minimum IPv6 MTU (1280).
	quote := pkt[:min(len(pkt), 1280-40-8)]

	out := make([]byte, 40+8+len(quote))
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:6], uint16(8+len(quote)))
	out[6] = protoICMPv6
	out[7] = 64
	copy(out[8:24], pkt[24:40])
	copy(out[24:40], pkt[8:24])

	icmp := out[40:]
	icmp[0], icmp[1] = 1, 1 // destination unreachable, administratively prohibited
	copy(icmp[8:], quote)
	binary.BigEndian.PutUint16(icmp[2:4], Checksum(icmp, pseudoSum6(out[8:40], len(icmp), protoICMPv6)))
	return out
}

// pseudoSum6 returns the unfolded sum of the IPv6 pseudo-header for addrs
// (src||dst, 32 bytes), upper-layer length and next header.
func pseudoSum6(addrs []byte, length int, next byte) uint32 {
	var acc uint32
	for i := 0; i < 32; i += 2 {
		acc += uint32(binary.BigEndian.Uint16(addrs[i:]))
	}
	return acc + uint32(length>>16) + uint32(length&0xffff) + uint32(next)
}
