// Package ipx contains minimal helpers to read source/destination addresses
// from raw IPv4/IPv6 packets for routing decisions.
package ipx

import "net"

// Version returns the IP version (4 or 6), or 0 if unknown.
func Version(pkt []byte) int {
	if len(pkt) < 1 {
		return 0
	}
	return int(pkt[0] >> 4)
}

// SrcIP returns the source address of an IP packet, or nil if it cannot be read.
func SrcIP(pkt []byte) net.IP {
	switch Version(pkt) {
	case 4:
		if len(pkt) < 20 {
			return nil
		}
		return net.IP(append([]byte(nil), pkt[12:16]...))
	case 6:
		if len(pkt) < 40 {
			return nil
		}
		return net.IP(append([]byte(nil), pkt[8:24]...))
	}
	return nil
}

// DstIP returns the destination address of an IP packet, or nil.
func DstIP(pkt []byte) net.IP {
	switch Version(pkt) {
	case 4:
		if len(pkt) < 20 {
			return nil
		}
		return net.IP(append([]byte(nil), pkt[16:20]...))
	case 6:
		if len(pkt) < 40 {
			return nil
		}
		return net.IP(append([]byte(nil), pkt[24:40]...))
	}
	return nil
}
