package node

import (
	"fmt"
	"log"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"goproxy/internal/config"
	"goproxy/internal/ipx"
	"goproxy/internal/keys"
	"goproxy/internal/nat"
	"goproxy/internal/noise"
	"goproxy/internal/transport"
	"goproxy/internal/tun"
)

// peer is a configured peer and its current sessions: at most one it opened to
// us (inbound) and one we opened to it (outbound). Both may be up at once when
// each side has the other's endpoint; the outbound one is then preferred.
type peer struct {
	// Fixed for the peer's lifetime: what its sessions are built on.
	name   string
	source string // "env" or "file"
	pub    keys.PublicKey
	psk    [32]byte
	tr     transport.Transport // stream transport for dialing; nil for udp or no endpoint

	// Replaced in place when only settings sessions do not depend on change
	// (routes, NAT, keepalive): see sessionEqual.
	cfg  atomic.Pointer[config.Peer]
	natp atomic.Pointer[nat.Table]      // source NAT of clients' traffic to the peer; nil = off
	srcs atomic.Pointer[[]netip.Prefix] // its routes: the source addresses it may use

	dev atomic.Pointer[tun.Device] // its own TUN (Interface) while open; nil = none

	stop     chan struct{} // closed when the peer is removed or the node stops
	stopOnce sync.Once

	mu  sync.Mutex
	in  *link
	out *link
}

func newPeer(pc *config.Peer, mark int, tunIP [4]byte) (*peer, error) {
	pub, err := pc.ParsePublicKey()
	if err != nil {
		return nil, err
	}
	p := &peer{name: pc.Name, pub: pub, psk: config.DerivePSK(pc.PSK), stop: make(chan struct{})}
	p.update(pc, tunIP)
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

// conf returns the peer's current configuration.
func (p *peer) conf() *config.Peer { return p.cfg.Load() }

// natTable returns the peer's NAT table, or nil when NAT is off.
func (p *peer) natTable() *nat.Table { return p.natp.Load() }

// update applies a configuration that differs from the current one at most
// in settings sessions do not depend on. A NAT table is kept while NAT stays on.
func (p *peer) update(pc *config.Peer, tunIP [4]byte) {
	switch {
	case !pc.NAT:
		p.natp.Store(nil)
	case p.natp.Load() == nil:
		t := nat.New(tunIP)
		t.Warn = func(msg string) { log.Printf("[%s] warning: %s", pc.Name, msg) }
		p.natp.Store(t)
	}
	srcs, _ := pc.Prefixes() // validated before
	p.srcs.Store(&srcs)
	p.cfg.Store(pc)
}

// accepts reports whether src is one of the peer's routes.
func (p *peer) accepts(src [4]byte) bool {
	a := netip.AddrFrom4(src)
	for _, pfx := range *p.srcs.Load() {
		if pfx.Contains(a) {
			return true
		}
	}
	return false
}

// device returns the peer's own TUN, or nil.
func (p *peer) device() *tun.Device { return p.dev.Load() }

// sessionEqual reports whether two configurations of a peer can share its
// sessions: the key, PSK and handed-out IP are part of the handshake, and the
// endpoint, transport and TLS settings of the outbound connection. The
// interface lives as long as the peer object.
func sessionEqual(a, b *config.Peer) bool {
	return a.Name == b.Name && a.PublicKey == b.PublicKey && a.PSK == b.PSK && a.IP == b.IP &&
		a.Endpoint == b.Endpoint && a.Transport == b.Transport && a.TLS == b.TLS && a.Interface == b.Interface
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

// shutdown stops the peer for good: its dial loop ends, its sessions close
// and its own TUN is removed.
func (p *peer) shutdown() {
	p.stopOnce.Do(func() { close(p.stop) })
	p.closeAll()
	if d := p.dev.Swap(nil); d != nil {
		d.Close()
	}
}

// stopped reports whether the peer was shut down.
func (p *peer) stopped() bool {
	select {
	case <-p.stop:
		return true
	default:
		return false
	}
}

// adopt attaches a new session to p unless p has been shut down meanwhile (a
// peer removed while its handshake was in flight); it reports whether it did.
func (p *peer) adopt(l *link) bool {
	p.attach(l)
	if p.stopped() {
		l.close()
		return false
	}
	return true
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
	if nt := p.natTable(); nt != nil && !nt.Out(pkt) {
		return
	}
	if l.localIP != 0 {
		ipx.RewriteSrc4(pkt, tunIP, ip4(l.localIP))
	}
	ipx.ClampMSS(pkt, l.mss)
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

	// mss caps the MSS of TCP handshakes through the link so segments fit the
	// tunnel (the smaller of both sides' MTU, minus IPv4 and TCP headers).
	mss uint16

	queue    chan []byte
	done     chan struct{}
	once     sync.Once
	lastSeen atomic.Int64 // unix nanos of the last datagram (accepted udp links)

	// For the status page.
	remote string    // the peer's address
	since  time.Time // when the session was established
	rx, tx atomic.Uint64
	lastRx atomic.Int64 // unix nanos of the last packet from the peer
}

func (n *Node) newLink(p *peer, outbound bool, sess session, mtu int) *link {
	sess.SetMaxPad(n.cfg.ObfsMaxPad)
	sess.SetMaxPayload(mtu)
	return &link{
		p:        p,
		outbound: outbound,
		sess:     sess,
		mss:      uint16(min(mtu, n.cfg.MTU) - 40),
		queue:    make(chan []byte, 512),
		done:     make(chan struct{}),
		since:    time.Now(),
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
				l.tx.Add(uint64(len(pkt)))
			}
		}
	}()
	ka := time.Duration(l.p.conf().KeepaliveSec) * time.Second
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
