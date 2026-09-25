package nat

import (
	"encoding/binary"
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
			if sport < tb.lo || sport > tb.hi {
				t.Fatalf("translated port %d outside %d-%d", sport, tb.lo, tb.hi)
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
	tb.lo, tb.hi, tb.next = 61000, 61001, 61000
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
