package node

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"goproxy/internal/config"
	"goproxy/internal/ipx"
	"goproxy/internal/keys"
	"goproxy/internal/nat"
	"goproxy/internal/noise"
	"goproxy/internal/transport"
)

// peer is a configured peer and its current sessions: at most one it opened to
// us (inbound) and one we opened to it (outbound). Both may be up at once when
// each side has the other's endpoint; the outbound one is then preferred.
type peer struct {
	cfg  *config.Peer
	name string
	pub  keys.PublicKey
	psk  [32]byte
	tr   transport.Transport // stream transport for dialing; nil for udp or no endpoint
	nat  *nat.Table          // source NAT of clients' traffic to the peer; nil = off

	mu  sync.Mutex
	in  *link
	out *link
}

func newPeer(pc *config.Peer, mark int, tunIP [4]byte) (*peer, error) {
	pub, err := pc.ParsePublicKey()
	if err != nil {
		return nil, err
	}
	p := &peer{cfg: pc, name: pc.Name, pub: pub, psk: config.DerivePSK(pc.PSK)}
	if pc.NAT {
		p.nat = nat.New(tunIP)
	}
	if pc.Endpoint != "" {
		switch pc.Transport {
		case "aead":
			p.tr = transport.NewTCPClient(mark)
		case "tls":
			p.tr = transport.NewTLSClient(pc.TLS.SNI, pc.TLS.Insecure, mark)
		case "udp":
			// datagram session, no stream transport
		default:
			return nil, fmt.Errorf("unknown transport %q", pc.Transport)
		}
	}
	return p, nil
}

// active returns the session to send through, preferring the outbound one.
func (p *peer) active() *link {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.out != nil {
		return p.out
	}
	return p.in
}

// attach makes l the peer's current session in its direction, closing the one
// it replaces (e.g. after the peer reconnected).
func (p *peer) attach(l *link) {
	p.mu.Lock()
	slot := &p.in
	if l.outbound {
		slot = &p.out
	}
	old := *slot
	*slot = l
	p.mu.Unlock()
	if old != nil {
		old.close()
	}
}

// detach forgets l if it is still one of the peer's current sessions.
func (p *peer) detach(l *link) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.in == l {
		p.in = nil
	}
	if p.out == l {
		p.out = nil
	}
}

func (p *peer) closeAll() {
	p.mu.Lock()
	in, out := p.in, p.out
	p.mu.Unlock()
	for _, l := range []*link{in, out} {
		if l != nil {
			l.close()
		}
	}
}

// send queues a packet from the TUN for this peer. Packets are dropped while
// no session is up.
func (p *peer) send(pkt []byte, tunIP [4]byte) {
	l := p.active()
	if l == nil {
		return
	}
	// Clients' traffic first takes the TUN address (NAT), which is then
	// translated to the IP the peer assigned to us, like the node's own.
	if p.nat != nil && !p.nat.Out(pkt) {
		return
	}
	if l.localIP != 0 {
		ipx.RewriteSrc4(pkt, tunIP, ip4(l.localIP))
	}
	select {
	case l.queue <- pkt:
	default:
		// Backpressure: drop rather than stall the TUN reader.
	}
}

// session is what a link needs from a stream Session, a dialed PacketConn or an
// accepted PacketSession.
type session interface {
	WritePacket(pkt []byte) error
	WriteKeepalive() error
	RunCover(maxInterval time.Duration, maxJunk int, stop <-chan struct{})
	SetMaxPad(n int)
	SetMaxPayload(n int)
}

// link is one established session with a peer.
type link struct {
	p        *peer
	outbound bool
	sess     session
	closeFn  func() // releases the transport; may be nil

	// localIP is the tunnel IP the peer assigned to us (outbound links only;
	// 0 = none): our TUN address is translated to it and back.
	localIP uint32

	queue    chan []byte
	done     chan struct{}
	once     sync.Once
	lastSeen atomic.Int64 // unix nanos of the last datagram (accepted udp links)
}

func (n *Node) newLink(p *peer, outbound bool, sess session, mtu int) *link {
	sess.SetMaxPad(n.cfg.ObfsMaxPad)
	sess.SetMaxPayload(mtu)
	return &link{
		p:        p,
		outbound: outbound,
		sess:     sess,
		queue:    make(chan []byte, 512),
		done:     make(chan struct{}),
	}
}

// start runs the link's writer and cover traffic (which also keeps NAT
// bindings alive) until it is closed.
func (n *Node) startLink(l *link) {
	go func() {
		for {
			select {
			case <-l.done:
				return
			case pkt := <-l.queue:
				if err := l.sess.WritePacket(pkt); err != nil {
					l.close()
					return
				}
			}
		}
	}()
	ka := time.Duration(l.p.cfg.KeepaliveSec) * time.Second
	if n.cfg.ObfsCover {
		go l.sess.RunCover(ka, noise.CoverMaxJunk, l.done)
	} else {
		go plainKeepalive(l.sess, ka, l.done)
	}
}

func (l *link) close() {
	l.once.Do(func() {
		close(l.done)
		l.p.detach(l)
		if l.closeFn != nil {
			l.closeFn()
		}
	})
}

// plainKeepalive sends a fixed-interval keepalive (used when cover traffic is off).
func plainKeepalive(sess session, interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		interval = 25 * time.Second
	}
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			if err := sess.WriteKeepalive(); err != nil {
				return
			}
		}
	}
}
