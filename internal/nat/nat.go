// Package nat is a small userspace source NAT (NAPT) for IPv4, used per peer
// (GOPROXY_PEER_<NAME>_NAT): packets from clients sent to the peer leave with
// the node's own address and a translated port, and the peer's replies are
// translated back. TCP and UDP are mapped by port, ICMP echo by identifier;
// ICMP errors about a mapped flow are translated too, embedded header
// included, so path-MTU discovery keeps working for the clients.
//
// Mappings are endpoint-dependent: a reply is translated only if it comes from
// the remote address and port the flow was opened to, so an unrelated inbound
// connection to the node never reaches a client. Flows the peer side opens to
// a client are remembered too, so the client's replies to them leave
// untranslated, as with conntrack.
package nat

import (
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"goproxy/internal/ipx"
)

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	tcpFIN = 0x01
	tcpRST = 0x04
)

// Idle timeouts of a mapping.
const (
	tcpTimeout     = time.Hour
	tcpDoneTimeout = time.Minute // after FIN or RST
	udpTimeout     = 3 * time.Minute
	icmpTimeout    = 30 * time.Second
)

// maxEntries bounds the table; new flows beyond it are dropped.
const maxEntries = 65536

// flow identifies a client's flow as it leaves the client.
type flow struct {
	proto uint8
	src   [4]byte
	sport uint16 // ICMP: echo identifier
	dst   [4]byte
	dport uint16 // ICMP: 0
}

// reply identifies the translated flow as the peer sees it.
type reply struct {
	proto uint8
	port  uint16 // translated source port / echo identifier
	dst   [4]byte
	dport uint16
}

type entry struct {
	f       flow
	port    uint16
	expires time.Time
}

// Table translates the flows of one peer.
type Table struct {
	addr   [4]byte // the node's address, which clients' flows leave with
	lo, hi uint16  // translated port range

	mu   sync.Mutex
	out  map[flow]*entry
	in   map[reply]*entry
	pass map[flow]time.Time // flows opened from the peer side (as the client replies), with expiry
	next uint16
}

// New returns a table translating to addr, with ports outside the host's
// ephemeral range so they never clash with the host's own sockets.
func New(addr [4]byte) *Table {
	lo, hi := portRange()
	return &Table{addr: addr, lo: lo, hi: hi, next: lo,
		out: map[flow]*entry{}, in: map[reply]*entry{}, pass: map[flow]time.Time{}}
}

// portRange picks the translated ports: above the ephemeral range if there is
// room (61000-65535 by default), otherwise below it.
func portRange() (uint16, uint16) {
	elo, ehi := 32768, 60999
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		if f := strings.Fields(string(b)); len(f) == 2 {
			if l, err1 := strconv.Atoi(f[0]); err1 == nil {
				if h, err2 := strconv.Atoi(f[1]); err2 == nil {
					elo, ehi = l, h
				}
			}
		}
	}
	if 65535-ehi >= 1024 {
		return uint16(ehi + 1), 65535
	}
	if elo-1024 >= 1024 {
		return 1024, uint16(elo - 1)
	}
	return 61000, 65535
}

// Out translates a packet from a client to the peer, in place. Packets from the
// node itself (source = addr), non-first fragments and protocols without ports
// pass unchanged. It returns false if the packet must be dropped (no free port
// or the table is full).
func (t *Table) Out(pkt []byte) bool {
	ihl, ok := header(pkt)
	if !ok || [4]byte(pkt[12:16]) == t.addr || fragment(pkt) {
		return true
	}
	f, ok := flowOf(pkt, ihl)
	if !ok {
		return true
	}
	now := time.Now()

	t.mu.Lock()
	if _, ok := t.pass[f]; ok {
		// A reply to a flow the peer side opened: leave it as it is.
		t.pass[f] = now.Add(timeout(pkt, ihl))
		t.mu.Unlock()
		return true
	}
	e := t.out[f]
	if e == nil {
		if len(t.out) >= maxEntries {
			t.mu.Unlock()
			return false
		}
		port, ok := t.allocate(f)
		if !ok {
			t.mu.Unlock()
			return false
		}
		e = &entry{f: f, port: port}
		t.out[f] = e
		t.in[reply{f.proto, port, f.dst, f.dport}] = e
	}
	e.expires = now.Add(timeout(pkt, ihl))
	port := e.port
	t.mu.Unlock()

	setAddr(pkt, ihl, 12, t.addr)
	setPort(pkt, ihl, true, port)
	return true
}

// In translates a packet from the peer back to the client, in place. It
// reports whether the packet belonged to a mapped flow (otherwise it is left
// unchanged, and remembered if it opens a flow to a client).
func (t *Table) In(pkt []byte) bool {
	ihl, ok := header(pkt)
	if !ok || fragment(pkt) {
		return false
	}
	if [4]byte(pkt[16:20]) != t.addr {
		t.remember(pkt, ihl)
		return false
	}
	if pkt[9] == protoICMP && len(pkt) >= ihl+8 && ipx.IsICMPv4Error(pkt) {
		return t.inError(pkt, ihl)
	}
	r, ok := replyOf(pkt, ihl)
	if !ok {
		return false
	}

	t.mu.Lock()
	e := t.in[r]
	if e == nil {
		t.mu.Unlock()
		return false
	}
	e.expires = time.Now().Add(timeout(pkt, ihl))
	f := e.f
	t.mu.Unlock()

	setAddr(pkt, ihl, 16, f.src)
	setPort(pkt, ihl, false, f.sport)
	return true
}

// inError translates an ICMP error about a mapped flow: the outer destination
// and the embedded packet's source address and port.
func (t *Table) inError(pkt []byte, ihl int) bool {
	icmp := pkt[ihl:]
	inner := icmp[8:]
	iihl, ok := header(inner)
	if !ok || [4]byte(inner[12:16]) != t.addr {
		return false
	}
	// The embedded packet is one we sent: its "source" side is the mapping.
	var r reply
	switch inner[9] {
	case protoTCP, protoUDP:
		if len(inner) < iihl+4 {
			return false
		}
		l4 := inner[iihl:]
		r = reply{inner[9], binary.BigEndian.Uint16(l4[0:2]), [4]byte(inner[16:20]), binary.BigEndian.Uint16(l4[2:4])}
	case protoICMP:
		if len(inner) < iihl+8 || inner[iihl] != 8 {
			return false
		}
		r = reply{protoICMP, binary.BigEndian.Uint16(inner[iihl+4:]), [4]byte(inner[16:20]), 0}
	default:
		return false
	}

	t.mu.Lock()
	e := t.in[r]
	t.mu.Unlock()
	if e == nil {
		return false
	}

	setAddr(pkt, ihl, 16, e.f.src)
	copy(inner[12:16], e.f.src[:])
	if inner[9] == protoICMP {
		binary.BigEndian.PutUint16(inner[iihl+4:], e.f.sport)
	} else {
		binary.BigEndian.PutUint16(inner[iihl:], e.f.sport)
	}
	binary.BigEndian.PutUint16(inner[10:12], 0)
	binary.BigEndian.PutUint16(inner[10:12], ipx.Checksum(inner[:iihl], 0))
	binary.BigEndian.PutUint16(icmp[2:4], 0)
	binary.BigEndian.PutUint16(icmp[2:4], ipx.Checksum(icmp, 0))
	return true
}

// remember records a flow the peer side sends to a client (not to the node's
// address), keyed as the client's replies will look, so Out leaves them alone.
func (t *Table) remember(pkt []byte, ihl int) {
	if pkt[9] != protoTCP && pkt[9] != protoUDP || len(pkt) < ihl+8 {
		return
	}
	l4 := pkt[ihl:]
	f := flow{
		proto: pkt[9],
		src:   [4]byte(pkt[16:20]),
		sport: binary.BigEndian.Uint16(l4[2:4]),
		dst:   [4]byte(pkt[12:16]),
		dport: binary.BigEndian.Uint16(l4[0:2]),
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.pass[f]; ok || len(t.pass) < maxEntries {
		t.pass[f] = time.Now().Add(timeout(pkt, ihl))
	}
}

// Expire drops mappings idle past their timeout.
func (t *Table) Expire() {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for f, e := range t.out {
		if now.After(e.expires) {
			delete(t.out, f)
			delete(t.in, reply{f.proto, e.port, f.dst, f.dport})
		}
	}
	for f, exp := range t.pass {
		if now.After(exp) {
			delete(t.pass, f)
		}
	}
}

// Len returns the number of mappings.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.out)
}

// allocate picks a translated port for f that is unused towards f's remote
// endpoint, preferring the client's own port. Called with t.mu held.
func (t *Table) allocate(f flow) (uint16, bool) {
	free := func(p uint16) bool {
		_, used := t.in[reply{f.proto, p, f.dst, f.dport}]
		return !used
	}
	if f.sport >= t.lo && f.sport <= t.hi && free(f.sport) {
		return f.sport, true
	}
	n := int(t.hi) - int(t.lo) + 1
	for i := 0; i < n; i++ {
		p := t.next
		if t.next == t.hi {
			t.next = t.lo
		} else {
			t.next++
		}
		if free(p) {
			return p, true
		}
	}
	return 0, false
}

// header validates an IPv4 header and returns its length.
func header(pkt []byte) (int, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return 0, false
	}
	return ihl, true
}

func fragment(pkt []byte) bool { return binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 }

// flowOf returns the flow of an outgoing packet: TCP/UDP by ports, ICMP echo
// requests by identifier.
func flowOf(pkt []byte, ihl int) (flow, bool) {
	l4 := pkt[ihl:]
	f := flow{proto: pkt[9], src: [4]byte(pkt[12:16]), dst: [4]byte(pkt[16:20])}
	switch f.proto {
	case protoTCP:
		if len(l4) < 20 {
			return f, false
		}
	case protoUDP:
		if len(l4) < 8 {
			return f, false
		}
	case protoICMP:
		if len(l4) < 8 || l4[0] != 8 {
			return f, false
		}
		f.sport = binary.BigEndian.Uint16(l4[4:6])
		return f, true
	default:
		return f, false
	}
	f.sport = binary.BigEndian.Uint16(l4[0:2])
	f.dport = binary.BigEndian.Uint16(l4[2:4])
	return f, true
}

// replyOf returns the key of an incoming packet: TCP/UDP by ports, ICMP echo
// replies by identifier.
func replyOf(pkt []byte, ihl int) (reply, bool) {
	l4 := pkt[ihl:]
	r := reply{proto: pkt[9], dst: [4]byte(pkt[12:16])}
	switch r.proto {
	case protoTCP, protoUDP:
		if len(l4) < 8 {
			return r, false
		}
		r.port = binary.BigEndian.Uint16(l4[2:4])
		r.dport = binary.BigEndian.Uint16(l4[0:2])
	case protoICMP:
		if len(l4) < 8 || l4[0] != 0 {
			return r, false
		}
		r.port = binary.BigEndian.Uint16(l4[4:6])
	default:
		return r, false
	}
	return r, true
}

// timeout returns how long a mapping stays after this packet.
func timeout(pkt []byte, ihl int) time.Duration {
	switch pkt[9] {
	case protoTCP:
		if len(pkt) >= ihl+14 && pkt[ihl+13]&(tcpFIN|tcpRST) != 0 {
			return tcpDoneTimeout
		}
		return tcpTimeout
	case protoUDP:
		return udpTimeout
	}
	return icmpTimeout
}

// l4Sum returns the offset of the checksum in the L4 header and whether the
// protocol's pseudo-header covers the IP addresses.
func l4Sum(proto byte) (off int, pseudo bool) {
	switch proto {
	case protoTCP:
		return 16, true
	case protoUDP:
		return 6, true
	}
	return 2, false // ICMP
}

// setAddr writes addr at off (12 = src, 16 = dst), fixing the IP and L4
// checksums.
func setAddr(pkt []byte, ihl, off int, addr [4]byte) {
	old := [4]byte(pkt[off : off+4])
	copy(pkt[off:off+4], addr[:])
	ipx.AdjustChecksum(pkt[10:12], old[:], addr[:], false)
	if sumOff, pseudo := l4Sum(pkt[9]); pseudo && len(pkt) >= ihl+sumOff+2 {
		ipx.AdjustChecksum(pkt[ihl+sumOff:ihl+sumOff+2], old[:], addr[:], pkt[9] == protoUDP)
	}
}

// setPort writes the source (src) or destination port -- for ICMP echo the
// identifier -- fixing the L4 checksum.
func setPort(pkt []byte, ihl int, src bool, port uint16) {
	l4 := pkt[ihl:]
	off := 2
	if src {
		off = 0
	}
	if pkt[9] == protoICMP {
		off = 4
	}
	var old, new [2]byte
	copy(old[:], l4[off:off+2])
	binary.BigEndian.PutUint16(new[:], port)
	copy(l4[off:off+2], new[:])
	sumOff, _ := l4Sum(pkt[9])
	ipx.AdjustChecksum(l4[sumOff:sumOff+2], old[:], new[:], pkt[9] == protoUDP)
}
