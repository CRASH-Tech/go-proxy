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
	"fmt"
	"net/netip"
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
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// Idle timeouts of a mapping, by the state of its flow (as conntrack does).
const (
	tcpTimeout       = time.Hour        // established
	tcpOpenTimeout   = 2 * time.Minute  // no reply yet
	tcpDoneTimeout   = time.Minute      // after FIN or RST from either side
	udpTimeout       = 30 * time.Second // one-off exchanges, e.g. a DNS query
	udpStreamTimeout = 3 * time.Minute  // traffic both ways, more than once
	icmpTimeout      = 30 * time.Second
)

// life tracks the state of a flow and when its mapping expires. Once a TCP
// flow is closing it stays so -- the final ACK after a FIN must not put it
// back to the established timeout -- until a new SYN reuses the ports.
type life struct {
	expires time.Time
	replied bool // a packet came back from the side that did not open the flow
	stream  bool // UDP: the opening side sent again after a reply
	closing bool // TCP: FIN or RST seen
}

// touch updates the state for a packet of the flow, sent by the side that
// opened it (opener) or by the other one, and extends the expiry.
func (l *life) touch(pkt []byte, ihl int, opener bool, now time.Time) {
	var d time.Duration
	switch pkt[9] {
	case protoTCP:
		flags := byte(0)
		if len(pkt) >= ihl+14 {
			flags = pkt[ihl+13]
		}
		if opener && flags&tcpSYN != 0 && flags&tcpACK == 0 { // a new connection on these ports
			*l = life{}
		}
		if !opener {
			l.replied = true
		}
		if flags&(tcpFIN|tcpRST) != 0 {
			l.closing = true
		}
		switch {
		case l.closing:
			d = tcpDoneTimeout
		case !l.replied:
			d = tcpOpenTimeout
		default:
			d = tcpTimeout
		}
	case protoUDP:
		if !opener {
			l.replied = true
		} else if l.replied {
			l.stream = true
		}
		d = udpTimeout
		if l.stream {
			d = udpStreamTimeout
		}
	default:
		d = icmpTimeout
	}
	l.expires = now.Add(d)
}

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
	life
	f    flow
	port uint16
}

// Table translates the flows of one peer.
type Table struct {
	addr  [4]byte     // the node's address, which clients' flows leave with
	spans [][2]uint16 // translated port ranges (inclusive)
	size  int         // number of ports in spans

	// Warn, if set, is told (at most once a minute) when flows are dropped
	// because no port is left.
	Warn func(string)

	mu       sync.Mutex
	out      map[flow]*entry
	in       map[reply]*entry
	pass     map[flow]*life // flows opened from the peer side, keyed as the client replies
	next     int            // allocation cursor, an index into spans
	lastWarn time.Time
}

// New returns a table translating to addr, with ports outside the host's
// ephemeral range so they never clash with the host's own sockets.
func New(addr [4]byte) *Table {
	t := &Table{addr: addr, out: map[flow]*entry{}, in: map[reply]*entry{}, pass: map[flow]*life{}}
	t.setSpans(portSpans())
	return t
}

func (t *Table) setSpans(spans [][2]uint16) {
	t.spans, t.size, t.next = spans, 0, 0
	for _, sp := range spans {
		t.size += int(sp[1]) - int(sp[0]) + 1
	}
}

// portAt returns the i-th translated port.
func (t *Table) portAt(i int) uint16 {
	for _, sp := range t.spans {
		n := int(sp[1]) - int(sp[0]) + 1
		if i < n {
			return sp[0] + uint16(i)
		}
		i -= n
	}
	return 0
}

func (t *Table) inSpans(p uint16) bool {
	for _, sp := range t.spans {
		if p >= sp[0] && p <= sp[1] {
			return true
		}
	}
	return false
}

// portSpans picks the translated ports: everything outside the host's
// ephemeral range (1024-32767 and 61000-65535 by default).
func portSpans() [][2]uint16 {
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
	var spans [][2]uint16
	if elo-1 >= 1024 {
		spans = append(spans, [2]uint16{1024, uint16(elo - 1)})
	}
	if ehi+1 <= 65535 {
		spans = append(spans, [2]uint16{uint16(ehi + 1), 65535})
	}
	if len(spans) == 0 { // the ephemeral range covers everything: share it
		spans = [][2]uint16{{61000, 65535}}
	}
	return spans
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
	if l := t.pass[f]; l != nil && now.Before(l.expires) {
		// A reply to a flow the peer side opened: leave it as it is.
		l.touch(pkt, ihl, false, now)
		t.mu.Unlock()
		return true
	}
	e := t.out[f]
	if e != nil && now.After(e.expires) {
		t.drop(e) // expired but not collected yet: start afresh
		e = nil
	}
	if e == nil {
		var port uint16
		ok := len(t.out) < maxEntries
		if ok {
			port, ok = t.allocate(f, now)
		}
		if !ok {
			t.exhausted(f, now)
			t.mu.Unlock()
			return false
		}
		e = &entry{f: f, port: port}
		t.out[f] = e
		t.in[reply{f.proto, port, f.dst, f.dport}] = e
	}
	e.touch(pkt, ihl, true, now)
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

	now := time.Now()
	t.mu.Lock()
	e := t.in[r]
	if e == nil || now.After(e.expires) {
		t.mu.Unlock()
		return false
	}
	e.touch(pkt, ihl, false, now)
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
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	l := t.pass[f]
	if l == nil {
		if len(t.pass) >= maxEntries {
			return
		}
		l = &life{}
		t.pass[f] = l
	}
	l.touch(pkt, ihl, true, now)
}

// Expire drops mappings idle past their timeout.
func (t *Table) Expire() {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, e := range t.out {
		if now.After(e.expires) {
			t.drop(e)
		}
	}
	for f, l := range t.pass {
		if now.After(l.expires) {
			delete(t.pass, f)
		}
	}
}

// drop removes a mapping. Called with t.mu held.
func (t *Table) drop(e *entry) {
	delete(t.out, e.f)
	delete(t.in, reply{e.f.proto, e.port, e.f.dst, e.f.dport})
}

// exhausted reports, at most once a minute, that a flow was dropped for lack
// of ports. Called with t.mu held.
func (t *Table) exhausted(f flow, now time.Time) {
	if t.Warn == nil || now.Sub(t.lastWarn) < time.Minute {
		return
	}
	t.lastWarn = now
	msg := fmt.Sprintf("NAT table full (%d flows): new connections are dropped", len(t.out))
	if len(t.out) < maxEntries {
		msg = fmt.Sprintf("NAT: all %d ports towards %s:%d are in use: new connections to it are dropped",
			t.size, netip.AddrFrom4(f.dst), f.dport)
	}
	go t.Warn(msg)
}

// Len returns the number of mappings.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.out)
}

// allocate picks a translated port for f that is unused towards f's remote
// endpoint, preferring the client's own port. A port whose mapping has expired
// but not been collected yet is taken over, and if none is left, the port of
// the oldest closing connection to the same endpoint. Called with t.mu held.
func (t *Table) allocate(f flow, now time.Time) (uint16, bool) {
	free := func(p uint16) bool {
		e := t.in[reply{f.proto, p, f.dst, f.dport}]
		if e != nil && now.After(e.expires) {
			t.drop(e)
			e = nil
		}
		return e == nil
	}
	if t.inSpans(f.sport) && free(f.sport) {
		return f.sport, true
	}
	for i := 0; i < t.size; i++ {
		p := t.portAt(t.next)
		t.next = (t.next + 1) % t.size
		if free(p) {
			return p, true
		}
	}
	var oldest *entry
	for _, e := range t.out {
		if e.closing && e.f.proto == f.proto && e.f.dst == f.dst && e.f.dport == f.dport &&
			(oldest == nil || e.expires.Before(oldest.expires)) {
			oldest = e
		}
	}
	if oldest == nil {
		return 0, false
	}
	t.drop(oldest)
	return oldest.port, true
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
