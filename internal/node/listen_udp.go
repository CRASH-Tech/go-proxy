package node

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"goproxy/internal/noise"
	"goproxy/internal/sockopt"
)

// minHandshakeMsg is the smallest possible message-1 (e + encStatic + empty
// encPayload). Datagrams smaller than this are never handshakes.
const minHandshakeMsg = 32 + 32 + 16 + 16

// udpIdleTimeout drops an accepted UDP session that has sent nothing (not even
// cover traffic) for this long.
const udpIdleTimeout = 150 * time.Second

// udpListener serves the datagram transport: one socket, demultiplexed by the
// sender's address to per-peer datagram sessions.
type udpListener struct {
	n  *Node
	pc *net.UDPConn

	mu     sync.Mutex
	byAddr map[string]udpSession
}

type udpSession struct {
	l  *link
	ps *noise.PacketSession
}

// listenUDP accepts peers over the udp transport. Socket errors are reported on
// errc; the returned func closes the socket.
func (n *Node) listenUDP(errc chan<- error) (func(), error) {
	lc := net.ListenConfig{Control: sockopt.UDPControl}
	packetConn, err := lc.ListenPacket(context.Background(), "udp", n.cfg.Listen)
	if err != nil {
		return nil, err
	}
	u := &udpListener{n: n, pc: packetConn.(*net.UDPConn), byAddr: map[string]udpSession{}}
	log.Printf("listening on %s (udp)", n.cfg.Listen)

	stop := make(chan struct{})
	go u.reap(stop)
	go func() {
		buf := make([]byte, 65535)
		for {
			m, raddr, err := u.pc.ReadFromUDP(buf)
			if err != nil {
				select {
				case errc <- err:
				default:
				}
				return
			}
			u.handleDatagram(raddr, buf[:m])
		}
	}()
	return func() {
		close(stop)
		u.pc.Close()
	}, nil
}

func (u *udpListener) handleDatagram(addr *net.UDPAddr, datagram []byte) {
	u.mu.Lock()
	s, ok := u.byAddr[addr.String()]
	u.mu.Unlock()

	if ok {
		pkt, isIP, err := s.ps.OpenPacket(datagram)
		if err == nil {
			s.l.lastSeen.Store(time.Now().UnixNano())
			if isIP {
				u.n.deliver(s.l, pkt)
			}
			return
		}
		// Decryption failed. If it is large enough to be a handshake, the peer
		// may have reconnected from the same address; fall through. Otherwise drop.
		if len(datagram) < minHandshakeMsg {
			return
		}
	}

	// New peer (or reconnect): treat the datagram as handshake message 1.
	u.handshake(addr, append([]byte(nil), datagram...))
}

func (u *udpListener) handshake(addr *net.UDPAddr, msg1 []byte) {
	n := u.n
	var p *peer
	write := func(b []byte) error {
		_, err := u.pc.WriteToUDP(b, addr)
		return err
	}
	ps, _, payload1, err := noise.RespondPacket(msg1, n.priv, n.authorizer(&p), write)
	if err != nil {
		return // probe/scanner or unauthorized; drop silently
	}
	if err := validHello(payload1); err != nil {
		return
	}

	key := addr.String()
	l := n.newLink(p, false, ps, n.cfg.MTU)
	l.lastSeen.Store(time.Now().UnixNano())
	l.closeFn = func() {
		u.mu.Lock()
		if u.byAddr[key].l == l {
			delete(u.byAddr, key)
		}
		u.mu.Unlock()
	}

	u.mu.Lock()
	old := u.byAddr[key]
	u.byAddr[key] = udpSession{l: l, ps: ps}
	u.mu.Unlock()
	if old.l != nil {
		old.l.close()
	}
	p.attach(l) // replaces the peer's session from another address, if any
	n.startLink(l)
	log.Printf("[%s] connected from %s (udp)", p.name, addr)
}

// reap closes accepted sessions that have gone silent.
func (u *udpListener) reap(stop <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		now := time.Now().UnixNano()
		var idle []*link
		u.mu.Lock()
		for _, s := range u.byAddr {
			if now-s.l.lastSeen.Load() > int64(udpIdleTimeout) {
				idle = append(idle, s.l)
			}
		}
		u.mu.Unlock()
		for _, l := range idle {
			l.close()
			log.Printf("[%s] timed out (udp)", l.p.name)
		}
	}
}
