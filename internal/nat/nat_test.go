package nat

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"goproxy/internal/ipx"
)

var (
	node   = [4]byte{10, 255, 255, 1}
	client = [4]byte{192, 168, 1, 10}
	remote = [4]byte{198, 51, 100, 1}
	other  = [4]byte{198, 51, 100, 2}
)

func pseudo(pkt []byte) uint32 {
	if pkt[9] == protoICMP {
		return 0
	}
	var acc uint32
	for i := 12; i < 20; i += 2 {
		acc += uint32(binary.BigEndian.Uint16(pkt[i:]))
	}
	return acc + uint32(pkt[9]) + uint32(len(pkt)-20)
}

// packet builds an IPv4 packet with valid checksums. l4 must hold the
// protocol header (ports / ICMP type+id); the checksum field is computed.
func packet(proto byte, src, dst [4]byte, l4 []byte) []byte {
	pkt := make([]byte, 20+len(l4))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	copy(pkt[20:], l4)
	binary.BigEndian.PutUint16(pkt[10:12], ipx.Checksum(pkt[:20], 0))
	off, _ := l4Sum(proto)
	binary.BigEndian.PutUint16(pkt[20+off:], 0)
	binary.BigEndian.PutUint16(pkt[20+off:], ipx.Checksum(pkt[20:], pseudo(pkt)))
	return pkt
}

func tcp(sport, dport uint16, flags byte) []byte {
	b := make([]byte, 40)
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	b[12] = 5 << 4
	b[13] = flags
	for i := 20; i < len(b); i++ {
		b[i] = byte(i * 13)
	}
	return b
}

func udp(sport, dport uint16) []byte {
	b := make([]byte, 30)
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	for i := 8; i < len(b); i++ {
		b[i] = byte(i * 7)
	}
	return b
}

func echo(typ byte, id uint16) []byte {
	b := make([]byte, 16)
	b[0] = typ
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], 1)
	return b
}

func verify(t *testing.T, pkt []byte) {
	t.Helper()
	if ipx.Checksum(pkt[:20], 0) != 0 {
		t.Fatal("bad IP header checksum")
	}
	if ipx.Checksum(pkt[20:], pseudo(pkt)) != 0 {
		t.Fatalf("bad L4 checksum (proto %d)", pkt[9])
	}
}

func ports(pkt []byte) (uint16, uint16) {
	return binary.BigEndian.Uint16(pkt[20:]), binary.BigEndian.Uint16(pkt[22:])
}

func TestRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		out   []byte
		sport uint16 // the client's source port
		back  func(port uint16) []byte
	}{
		{"tcp", packet(protoTCP, client, remote, tcp(40000, 443, 0x02)), 40000,
			func(p uint16) []byte { return packet(protoTCP, remote, node, tcp(443, p, 0x12)) }},
		{"udp", packet(protoUDP, client, remote, udp(5353, 53)), 5353,
			func(p uint16) []byte { return packet(protoUDP, remote, node, udp(53, p)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tb := New(node)
			pkt := tc.out
			if !tb.Out(pkt) {
				t.Fatal("dropped")
			}
			verify(t, pkt)
			if ipx.SrcIP(pkt).String() != "10.255.255.1" {
				t.Fatalf("src = %s", ipx.SrcIP(pkt))
			}
			sport, _ := ports(pkt)
			if !tb.inSpans(sport) {
				t.Fatalf("translated port %d outside %v", sport, tb.spans)
			}

			reply := tc.back(sport)
			if !tb.In(reply) {
				t.Fatal("reply not translated")
			}
			verify(t, reply)
			if ipx.DstIP(reply).String() != "192.168.1.10" {
				t.Fatalf("dst = %s", ipx.DstIP(reply))
			}
			if _, dport := ports(reply); dport != tc.sport {
				t.Fatalf("dport = %d, want the client's %d", dport, tc.sport)
			}
		})
	}
}

func TestSameFlowSamePort(t *testing.T) {
	tb := New(node)
	a := packet(protoTCP, client, remote, tcp(40000, 443, 0x02))
	b := packet(protoTCP, client, remote, tcp(40000, 443, 0x10))
	c := packet(protoTCP, client, remote, tcp(40001, 443, 0x02))
	tb.Out(a)
	tb.Out(b)
	tb.Out(c)
	pa, _ := ports(a)
	pb, _ := ports(b)
	pc, _ := ports(c)
	if pa != pb || pa == pc {
		t.Fatalf("ports %d %d %d: one flow must keep its port, another must differ", pa, pb, pc)
	}
	if tb.Len() != 2 {
		t.Fatalf("%d mappings, want 2", tb.Len())
	}
}

func TestNodeTrafficUntouched(t *testing.T) {
	tb := New(node)
	pkt := packet(protoTCP, node, remote, tcp(40000, 443, 0x02))
	orig := append([]byte(nil), pkt...)
	tb.Out(pkt)
	if string(pkt) != string(orig) || tb.Len() != 0 {
		t.Fatal("the node's own packet was translated")
	}
	// ...and an inbound packet with no mapping is left alone.
	in := packet(protoTCP, remote, node, tcp(443, 40000, 0x12))
	orig = append([]byte(nil), in...)
	if tb.In(in) || string(in) != string(orig) {
		t.Fatal("an unmapped packet was translated")
	}
}

func TestEndpointDependent(t *testing.T) {
	tb := New(node)
	pkt := packet(protoUDP, client, remote, udp(5353, 53))
	tb.Out(pkt)
	port, _ := ports(pkt)
	for _, from := range []struct {
		addr [4]byte
		port uint16
	}{{other, 53}, {remote, 54}} {
		if tb.In(packet(protoUDP, from.addr, node, udp(from.port, port))) {
			t.Fatalf("translated a packet from %v:%d, not the flow's remote", from.addr, from.port)
		}
	}
}

func TestICMPEcho(t *testing.T) {
	tb := New(node)
	req := packet(protoICMP, client, remote, echo(8, 777))
	if !tb.Out(req) {
		t.Fatal("dropped")
	}
	verify(t, req)
	id := binary.BigEndian.Uint16(req[24:])
	rep := packet(protoICMP, remote, node, echo(0, id))
	if !tb.In(rep) {
		t.Fatal("echo reply not translated")
	}
	verify(t, rep)
	if binary.BigEndian.Uint16(rep[24:]) != 777 || ipx.DstIP(rep).String() != "192.168.1.10" {
		t.Fatal("echo reply not restored")
	}
}

func TestICMPErrorInner(t *testing.T) {
	tb := New(node)
	out := packet(protoTCP, client, remote, tcp(40000, 443, 0x10))
	tb.Out(out)
	nport, _ := ports(out)

	// A router reports "fragmentation needed" for the translated segment.
	router := [4]byte{203, 0, 113, 1}
	body := append([]byte{3, 4, 0, 0, 0, 0, 0x05, 0x00}, out[:28]...)
	icmpErr := packet(protoICMP, router, node, body)
	if !tb.In(icmpErr) {
		t.Fatal("ICMP error not translated")
	}
	verify(t, icmpErr)
	inner := icmpErr[28:]
	if ipx.DstIP(icmpErr).String() != "192.168.1.10" || ipx.SrcIP(inner).String() != "192.168.1.10" {
		t.Fatalf("outer dst %s, inner src %s", ipx.DstIP(icmpErr), ipx.SrcIP(inner))
	}
	if sp := binary.BigEndian.Uint16(inner[20:]); sp != 40000 {
		t.Fatalf("inner source port %d (translated was %d)", sp, nport)
	}
	if ipx.Checksum(inner[:20], 0) != 0 {
		t.Fatal("bad inner header checksum")
	}
}

func TestExpire(t *testing.T) {
	tb := New(node)
	pkt := packet(protoTCP, client, remote, tcp(40000, 443, tcpRST))
	tb.Out(pkt)
	tb.mu.Lock()
	for _, e := range tb.out {
		e.expires = time.Now().Add(-time.Second)
	}
	tb.mu.Unlock()
	tb.Expire()
	if tb.Len() != 0 || len(tb.in) != 0 {
		t.Fatal("expired mapping kept")
	}
}

func TestFull(t *testing.T) {
	tb := New(node)
	tb.setSpans([][2]uint16{{61000, 61001}})
	for i := uint16(0); i < 2; i++ {
		if !tb.Out(packet(protoUDP, client, remote, udp(1000+i, 53))) {
			t.Fatal("dropped while ports are free")
		}
	}
	if tb.Out(packet(protoUDP, client, remote, udp(1002, 53))) {
		t.Fatal("accepted a flow with no free port")
	}
	// A different remote endpoint may reuse the ports.
	if !tb.Out(packet(protoUDP, client, other, udp(1002, 53))) {
		t.Fatal("ports not reused towards another endpoint")
	}
}

func TestPeerOpenedFlowUntranslated(t *testing.T) {
	tb := New(node)
	// A host behind the peer opens a connection to the client...
	syn := packet(protoTCP, remote, client, tcp(50000, 22, 0x02))
	if tb.In(syn) {
		t.Fatal("a packet to the client was translated")
	}
	// ...so the client's replies must leave with its own address and port.
	synack := packet(protoTCP, client, remote, tcp(22, 50000, 0x12))
	orig := append([]byte(nil), synack...)
	if !tb.Out(synack) || string(synack) != string(orig) {
		t.Fatal("a reply to a peer-opened flow was translated")
	}
	if tb.Len() != 0 {
		t.Fatal("a mapping was created for a peer-opened flow")
	}
	// A new flow from the client to the same host is still translated.
	other := packet(protoTCP, client, remote, tcp(40000, 22, 0x02))
	tb.Out(other)
	if ipx.SrcIP(other).String() != "10.255.255.1" {
		t.Fatal("a client-opened flow was not translated")
	}
}

// connect runs a whole TCP connection from the client through tb: handshake,
// data, and a graceful close from both sides.
func connect(t *testing.T, tb *Table, sport uint16) bool {
	t.Helper()
	send := func(flags byte) (uint16, bool) {
		p := packet(protoTCP, client, remote, tcp(sport, 443, flags))
		if !tb.Out(p) {
			return 0, false
		}
		n, _ := ports(p)
		return n, true
	}
	recv := func(nport uint16, flags byte) { tb.In(packet(protoTCP, remote, node, tcp(443, nport, flags))) }

	n, ok := send(0x02) // SYN
	if !ok {
		return false
	}
	recv(n, 0x12) // SYN-ACK
	send(0x10)    // ACK
	send(0x18)    // data
	recv(n, 0x18) // data
	send(0x11)    // FIN-ACK
	recv(n, 0x11) // FIN-ACK
	send(0x10)    // final ACK
	return true
}

func TestClosedTCPReleasesPortSoon(t *testing.T) {
	tb := New(node)
	connect(t, tb, 40000)
	tb.mu.Lock()
	defer tb.mu.Unlock()
	for _, e := range tb.out {
		if left := time.Until(e.expires); left > 2*tcpDoneTimeout {
			t.Fatalf("a closed connection keeps its port for %s", left.Round(time.Minute))
		}
	}
}

func TestManyShortConnectionsToOneEndpoint(t *testing.T) {
	tb := New(node)
	tb.setSpans([][2]uint16{{61000, 61003}}) // 4 ports
	for i := 0; i < 50; i++ {
		if !connect(t, tb, uint16(40000+i)) {
			t.Fatalf("connection %d dropped: ports of closed connections are not reused", i+1)
		}
		// Time passes between connections: closed ones become reclaimable.
		tb.mu.Lock()
		for _, e := range tb.out {
			if e.closing {
				e.expires = time.Now().Add(-time.Second)
			}
		}
		tb.mu.Unlock()
	}
}

// expiry returns how long the only mapping in tb has left.
func expiry(t *testing.T, tb *Table) time.Duration {
	t.Helper()
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if len(tb.out) != 1 {
		t.Fatalf("%d mappings, want 1", len(tb.out))
	}
	for _, e := range tb.out {
		return time.Until(e.expires).Round(time.Second)
	}
	return 0
}

func TestTimeoutsByState(t *testing.T) {
	// A DNS-like exchange: one query, one answer.
	tb := New(node)
	q := packet(protoUDP, client, remote, udp(5353, 53))
	tb.Out(q)
	n, _ := ports(q)
	tb.In(packet(protoUDP, remote, node, udp(53, n)))
	if d := expiry(t, tb); d != udpTimeout {
		t.Fatalf("one-off UDP exchange: %s, want %s", d, udpTimeout)
	}
	// The client sends again: a stream.
	tb.Out(packet(protoUDP, client, remote, udp(5353, 53)))
	if d := expiry(t, tb); d != udpStreamTimeout {
		t.Fatalf("UDP stream: %s, want %s", d, udpStreamTimeout)
	}

	// A SYN nobody answers.
	tb = New(node)
	tb.Out(packet(protoTCP, client, remote, tcp(40000, 443, 0x02)))
	if d := expiry(t, tb); d != tcpOpenTimeout {
		t.Fatalf("unanswered SYN: %s, want %s", d, tcpOpenTimeout)
	}
}

func TestExhaustionWarnsOnce(t *testing.T) {
	tb := New(node)
	tb.setSpans([][2]uint16{{61000, 61000}}) // 1 port
	warned := make(chan string, 10)
	tb.Warn = func(msg string) { warned <- msg }
	tb.Out(packet(protoTCP, client, remote, tcp(40000, 443, 0x02)))
	for i := 0; i < 5; i++ {
		if tb.Out(packet(protoTCP, client, remote, tcp(uint16(40001+i), 443, 0x02))) {
			t.Fatal("a flow got a port that is in use")
		}
	}
	select {
	case msg := <-warned:
		if !strings.Contains(msg, "198.51.100.1:443") {
			t.Fatalf("warning %q does not name the endpoint", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("no warning")
	}
	time.Sleep(50 * time.Millisecond)
	if len(warned) != 0 {
		t.Fatalf("%d more warnings within a minute", len(warned))
	}
}

func TestPortSpansAvoidEphemeral(t *testing.T) {
	tb := New(node)
	if tb.size < 30000 {
		t.Fatalf("only %d ports: %v", tb.size, tb.spans)
	}
	if tb.inSpans(40000) || tb.inSpans(80) || !tb.inSpans(1024) || !tb.inSpans(65535) {
		t.Fatalf("spans %v overlap the ephemeral or privileged ports", tb.spans)
	}
	// Two spans: every index maps to a distinct port inside them.
	tb.setSpans([][2]uint16{{2000, 2001}, {3000, 3000}})
	got := []uint16{tb.portAt(0), tb.portAt(1), tb.portAt(2)}
	if got[0] != 2000 || got[1] != 2001 || got[2] != 3000 || tb.size != 3 {
		t.Fatalf("portAt = %v, size %d", got, tb.size)
	}
}

func TestClosingPortTakenWhenFull(t *testing.T) {
	tb := New(node)
	tb.setSpans([][2]uint16{{61000, 61001}}) // 2 ports
	connect(t, tb, 40000)                    // closed: closing, not expired yet
	connect(t, tb, 40001)
	// Both ports belong to closing connections; a new one takes the oldest.
	if !connect(t, tb, 40002) {
		t.Fatal("new connection dropped although closing ports could be reused")
	}
	// A live connection is never taken over.
	tb = New(node)
	tb.setSpans([][2]uint16{{61000, 61000}})
	tb.Out(packet(protoTCP, client, remote, tcp(40000, 443, 0x02)))
	if tb.Out(packet(protoTCP, client, remote, tcp(40001, 443, 0x02))) {
		t.Fatal("a live connection's port was taken over")
	}
}
