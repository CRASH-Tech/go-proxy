package flowlog

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

type capture struct{ lines []string }

func (c *capture) logf(format string, args ...any) {
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func ip4(proto byte, src, dst [4]byte, l4 []byte) []byte {
	pkt := make([]byte, 20+len(l4))
	pkt[0] = 0x45
	pkt[9] = proto
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	copy(pkt[20:], l4)
	return pkt
}

func ports(sport, dport uint16) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	return b
}

func echo(typ byte, id uint16) []byte {
	b := make([]byte, 8)
	b[0] = typ
	binary.BigEndian.PutUint16(b[4:], id)
	return b
}

var (
	client = [4]byte{192, 168, 1, 10}
	server = [4]byte{142, 250, 74, 46}
)

func TestNewFlowLoggedOnce(t *testing.T) {
	c := &capture{}
	l := New(c.logf)
	out := ip4(protoTCP, client, server, ports(51234, 443))
	back := ip4(protoTCP, server, client, ports(443, 51234))

	l.Seen(out, "via EXIT")
	l.Seen(back, "from EXIT") // the reply
	l.Seen(out, "via EXIT")   // more of the same flow

	want := "conn tcp 192.168.1.10:51234 -> 142.250.74.46:443 via EXIT"
	if len(c.lines) != 1 || c.lines[0] != want {
		t.Fatalf("lines = %q, want [%q]", c.lines, want)
	}
}

func TestFlowFromPeer(t *testing.T) {
	c := &capture{}
	l := New(c.logf)
	laptop := [4]byte{10, 1, 254, 2}
	host := [4]byte{10, 1, 20, 254}
	l.Seen(ip4(protoUDP, laptop, host, ports(5353, 53)), "from LAPTOP")
	l.Seen(ip4(protoUDP, host, laptop, ports(53, 5353)), "via LAPTOP") // our reply

	want := "conn udp 10.1.254.2:5353 -> 10.1.20.254:53 from LAPTOP"
	if len(c.lines) != 1 || c.lines[0] != want {
		t.Fatalf("lines = %q, want [%q]", c.lines, want)
	}
}

func TestICMPEcho(t *testing.T) {
	c := &capture{}
	l := New(c.logf)
	l.Seen(ip4(protoICMP, server, client, echo(0, 7)), "from EXIT") // a stray reply: no flow
	l.Seen(ip4(protoICMP, client, server, echo(8, 7)), "via EXIT")
	l.Seen(ip4(protoICMP, server, client, echo(0, 7)), "from EXIT")
	l.Seen(ip4(protoICMP, client, server, echo(3, 7)), "via EXIT") // not echo: ignored

	want := "conn icmp 192.168.1.10 -> 142.250.74.46 (echo id 7) via EXIT"
	if len(c.lines) != 1 || c.lines[0] != want {
		t.Fatalf("lines = %q, want [%q]", c.lines, want)
	}
}

func TestExpireLogsAgain(t *testing.T) {
	c := &capture{}
	l := New(c.logf)
	out := ip4(protoUDP, client, server, ports(40000, 53))
	l.Seen(out, "via EXIT")
	l.mu.Lock()
	for k := range l.flows {
		l.flows[k] = time.Now().Add(-time.Second)
	}
	l.mu.Unlock()
	l.Expire()
	l.Seen(out, "via EXIT")
	if len(c.lines) != 2 {
		t.Fatalf("lines = %q, want the flow logged again after expiry", c.lines)
	}
}

func TestBlocked(t *testing.T) {
	c := &capture{}
	l := New(c.logf)
	syn := ip4(protoTCP, client, [4]byte{1, 2, 3, 4}, ports(40000, 443))
	l.Blocked(syn)
	l.Blocked(syn) // a retransmission

	v6 := make([]byte, 40)
	v6[0] = 0x60
	v6[8], v6[9], v6[23] = 0xfd, 0x00, 1   // fd00::1
	v6[24], v6[25], v6[39] = 0x20, 0x01, 1 // 2001::1
	l.Blocked(v6)
	l.Blocked(v6)

	if len(c.lines) != 2 ||
		c.lines[0] != "conn tcp 192.168.1.10:40000 -> 1.2.3.4:443 blocked" ||
		!strings.HasPrefix(c.lines[1], "conn ipv6 fd00::1 -> 2001::1 blocked") {
		t.Fatalf("lines = %q", c.lines)
	}
}

func TestIgnoresFragmentsAndGarbage(t *testing.T) {
	c := &capture{}
	l := New(c.logf)
	frag := ip4(protoTCP, client, server, ports(51234, 443))
	binary.BigEndian.PutUint16(frag[6:8], 100) // non-first fragment
	l.Seen(frag, "via EXIT")
	l.Seen([]byte{0x45, 0, 0}, "via EXIT")
	if len(c.lines) != 0 {
		t.Fatalf("lines = %q", c.lines)
	}
}
