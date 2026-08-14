// Package sockopt provides Dialer/ListenConfig Control hooks that make the outer
// connection robust to reduced or mis-discovered path MTUs — a common cause of
// "pages load halfway" over a tunnel.
package sockopt

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// OuterTCPMSS clamps the outer TCP connection's segment size so its packets fit
// conservative (often tunneled) path MTUs even when PMTU discovery is broken on
// the path. 1360 => outer IP packet ~1400 bytes.
const OuterTCPMSS = 1360

// TCPControl clamps TCP_MAXSEG on the socket before connect/listen, so the MSS
// advertised in the handshake keeps both directions' segments small enough.
func TCPControl(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, OuterTCPMSS)
	}); err != nil {
		return err
	}
	return serr
}

// UDPControl disables path-MTU discovery on the UDP socket, so an oversized
// datagram is fragmented rather than dropped with EMSGSIZE. Padding is already
// bounded to the tunnel MTU, so this is only a safety net for smaller paths.
func UDPControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DONT)
	})
}
