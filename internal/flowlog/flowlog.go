// Package flowlog logs the connections that pass through a node
// (GOPROXY_LOG_CONNECTIONS): one line when a flow starts -- who, where, and
// through which peer -- and nothing for the rest of its packets or its
// replies. TCP and UDP flows are keyed by ports, ICMP echo by identifier.
package flowlog

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

// Idle times after which a flow is forgotten (and logged again if it resumes).
const (
	tcpIdle   = 10 * time.Minute
	otherIdle = time.Minute
)

// maxFlows bounds the table; beyond it, new flows are not logged.
const maxFlows = 65536

type key struct {
	proto      uint8
	src, dst   [4]byte
	sport, dpt uint16 // ICMP: echo identifier, 0
}

// Logger remembers recent flows so each is logged once.
type Logger struct {
	logf func(format string, args ...any)

	mu    sync.Mutex
	flows map[key]time.Time      // expiry
	v6    map[[32]byte]time.Time // blocked IPv6 src||dst, expiry
	full  bool
}

// New returns a Logger writing through logf (e.g. log.Printf).
func New(logf func(format string, args ...any)) *Logger {
	return &Logger{logf: logf, flows: map[key]time.Time{}, v6: map[[32]byte]time.Time{}}
}

// Seen records a packet of a flow and logs the flow if it is new. how says
// where it goes or comes from, e.g. "via EXIT" or "from LAPTOP". Replies to a
// known flow are not logged.
func (l *Logger) Seen(pkt []byte, how string) {
	k, rev, start, ok := parse(pkt)
	if !ok {
		return
	}
	l.touch(k, rev, start, how)
}

// Blocked logs a flow that no peer routes (once per flow).
func (l *Logger) Blocked(pkt []byte) {
	if len(pkt) >= 40 && pkt[0]>>4 == 6 {
		pair := [32]byte(pkt[8:40])
		l.mu.Lock()
		_, known := l.v6[pair]
		if !known && len(l.v6) < maxFlows {
			l.v6[pair] = time.Now().Add(otherIdle)
		}
		l.mu.Unlock()
		if !known {
			src := netip.AddrFrom16([16]byte(pkt[8:24]))
			dst := netip.AddrFrom16([16]byte(pkt[24:40]))
			l.logf("conn ipv6 %s -> %s blocked", src, dst)
		}
		return
	}
	k, rev, start, ok := parse(pkt)
	if !ok {
		return
	}
	l.touch(k, rev, start, "blocked")
}

func (l *Logger) touch(k, rev key, start bool, how string) {
	now := time.Now()
	idle := otherIdle
	if k.proto == protoTCP {
		idle = tcpIdle
	}

	l.mu.Lock()
	if _, ok := l.flows[rev]; ok { // a reply
		l.flows[rev] = now.Add(idle)
		l.mu.Unlock()
		return
	}
	_, known := l.flows[k]
	if known {
		l.flows[k] = now.Add(idle)
		l.mu.Unlock()
		return
	}
	if !start {
		l.mu.Unlock()
		return // e.g. an echo reply for a flow we never saw
	}
	if len(l.flows) >= maxFlows {
		warn := !l.full
		l.full = true
		l.mu.Unlock()
		if warn {
			l.logf("conn: connection table full (%d flows), new connections are not logged", maxFlows)
		}
		return
	}
	l.flows[k] = now.Add(idle)
	l.mu.Unlock()

	l.logf("conn %s %s %s", protoName(k.proto), arrow(k), how)
}

// Expire forgets flows idle past their timeout.
func (l *Logger) Expire() {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, exp := range l.flows {
		if now.After(exp) {
			delete(l.flows, k)
		}
	}
	for pair, exp := range l.v6 {
		if now.After(exp) {
			delete(l.v6, pair)
		}
	}
	if len(l.flows) < maxFlows {
		l.full = false
	}
}

// parse returns the flow key of an IPv4 packet, the key its replies would
// have, and whether the packet may start a flow (anything but an echo reply).
func parse(pkt []byte) (k, rev key, start, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return k, rev, false, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl || binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return k, rev, false, false
	}
	l4 := pkt[ihl:]
	k = key{proto: pkt[9], src: [4]byte(pkt[12:16]), dst: [4]byte(pkt[16:20])}
	switch k.proto {
	case protoTCP, protoUDP:
		if len(l4) < 4 {
			return k, rev, false, false
		}
		k.sport = binary.BigEndian.Uint16(l4[0:2])
		k.dpt = binary.BigEndian.Uint16(l4[2:4])
		rev = key{k.proto, k.dst, k.src, k.dpt, k.sport}
		return k, rev, true, true
	case protoICMP:
		if len(l4) < 8 || (l4[0] != 8 && l4[0] != 0) { // echo request / reply only
			return k, rev, false, false
		}
		k.sport = binary.BigEndian.Uint16(l4[4:6])
		rev = key{k.proto, k.dst, k.src, k.sport, 0}
		return k, rev, l4[0] == 8, true
	}
	return k, rev, false, false
}

func protoName(proto uint8) string {
	switch proto {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	}
	return "icmp"
}

func arrow(k key) string {
	src, dst := netip.AddrFrom4(k.src), netip.AddrFrom4(k.dst)
	if k.proto == protoICMP {
		return fmt.Sprintf("%s -> %s (echo id %d)", src, dst, k.sport)
	}
	return fmt.Sprintf("%s:%d -> %s:%d", src, k.sport, dst, k.dpt)
}
