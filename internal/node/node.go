// Package node implements goproxy's only role. A node owns one TUN device and
// exchanges IP packets with its peers over encrypted, obfuscated sessions: it
// accepts peers that connect to it (GOPROXY_LISTEN) and connects to the peers
// that have an endpoint. Every packet read from the TUN goes to the peer whose
// routes contain its destination (longest prefix wins); packets no peer routes
// are blocked. Which traffic reaches the TUN is up to the host's routes -- set
// by the admin, or pushed from the peers' routes with GOPROXY_PUSH_ROUTES.
// NAT to the internet is the host's too, or GOPROXY_MASQUERADE; forwarding
// (ip_forward) is always the admin's.
package node

import (
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"goproxy/internal/config"
	"goproxy/internal/fallback"
	"goproxy/internal/flowlog"
	"goproxy/internal/hostnat"
	"goproxy/internal/hostroute"
	"goproxy/internal/ipx"
	"goproxy/internal/keys"
	"goproxy/internal/route"
	"goproxy/internal/tun"
)

// Node is a running goproxy node.
type Node struct {
	cfg    *config.NodeConfig
	priv   keys.PrivateKey
	tunIP  [4]byte
	tunNet string // the TUN's network, told to connecting peers
	fb     *fallback.Handler

	peers  []*peer
	byKey  map[keys.PublicKey]*peer
	routes route.Table[*peer]
	flows  *flowlog.Logger // nil unless GOPROXY_LOG_CONNECTIONS

	dev *tun.Device
}

// New builds a Node (its peers and route table) from configuration.
func New(cfg *config.NodeConfig) (*Node, error) {
	priv, err := cfg.ParsePrivateKey()
	if err != nil {
		return nil, err
	}
	addr, err := netip.ParsePrefix(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("tun address: %w", err)
	}
	fb, err := fallback.New(cfg.FallbackMode, cfg.FallbackStatus, cfg.FallbackURL, cfg.FallbackTarget)
	if err != nil {
		return nil, err
	}
	n := &Node{
		cfg:    cfg,
		priv:   priv,
		tunIP:  addr.Addr().As4(),
		tunNet: addr.Masked().String(),
		fb:     fb,
		byKey:  map[keys.PublicKey]*peer{},
	}
	if cfg.LogConns {
		n.flows = flowlog.New(log.Printf)
	}
	for i := range cfg.Peers {
		p, err := newPeer(&cfg.Peers[i], cfg.FwMark, addr.Addr().As4())
		if err != nil {
			return nil, fmt.Errorf("peer %q: %w", cfg.Peers[i].Name, err)
		}
		prefixes, err := p.cfg.Prefixes()
		if err != nil {
			return nil, fmt.Errorf("peer %q: %w", p.name, err)
		}
		for _, pfx := range prefixes {
			if err := n.routes.Insert(pfx, p); err != nil {
				return nil, fmt.Errorf("peer %q route: %w", p.name, err)
			}
		}
		n.peers = append(n.peers, p)
		n.byKey[p.pub] = p
	}
	return n, nil
}

// Run opens and configures the TUN, starts the listener and the connections to
// peers, and blocks until stop is closed or the listener fails.
func (n *Node) Run(stop <-chan struct{}) error {
	dev, err := tun.Open(n.cfg.InterfaceName)
	if err != nil {
		return err
	}
	n.dev = dev
	defer dev.Close()
	if err := dev.Configure(n.cfg.Address, n.cfg.MTU); err != nil {
		return err
	}
	log.Printf("tun %s up (%s, mtu %d); %d peer(s); destinations without a peer are blocked",
		dev.Name(), n.cfg.Address, n.cfg.MTU, len(n.peers))
	if n.cfg.PushRoutes != "false" {
		var prefixes []netip.Prefix
		for _, p := range n.peers {
			pfx, _ := p.cfg.Prefixes() // validated in New
			prefixes = append(prefixes, pfx...)
		}
		warn := func(msg string) { log.Printf("push routes: warning: %s", msg) }
		scope, whom := hostroute.All, "host and clients"
		if n.cfg.PushRoutes == "clients" {
			scope, whom = hostroute.Clients, "clients only"
		}
		unpush, err := hostroute.Push(scope, dev.Name(), n.cfg.FwMark, prefixes, warn)
		if err != nil {
			return fmt.Errorf("push routes: %w", err)
		}
		defer unpush()
		log.Printf("pushed the peers' %d route(s) into %s (%s)", len(prefixes), dev.Name(), whom)
	}
	if n.cfg.Masquerade != "" {
		networks := n.cfg.MasqueradeIPs
		if len(networks) == 0 {
			networks = []string{n.tunNet}
		}
		warn := func(msg string) { log.Printf("masquerade: warning: %s", msg) }
		unmasq, err := hostnat.Masquerade(networks, n.cfg.Masquerade, warn)
		if err != nil {
			return fmt.Errorf("masquerade: %w", err)
		}
		defer unmasq()
		log.Printf("masquerading %s out of %s", strings.Join(networks, ", "), n.cfg.Masquerade)
	}

	errc := make(chan error, 1)
	closeListener := func() {}
	if n.cfg.Listen != "" {
		if n.cfg.Transport == "udp" {
			closeListener, err = n.listenUDP(errc)
		} else {
			closeListener, err = n.listenStream(errc)
		}
		if err != nil {
			return err
		}
	}

	quit := make(chan struct{})
	var wg sync.WaitGroup
	for _, p := range n.peers {
		if p.cfg.Endpoint == "" {
			continue
		}
		wg.Add(1)
		go func(p *peer) {
			defer wg.Done()
			n.dialLoop(p, quit)
		}(p)
	}
	go n.tunReader()
	go n.housekeeping(quit)

	var runErr error
	select {
	case <-stop:
	case runErr = <-errc:
	}
	close(quit)
	closeListener()
	for _, p := range n.peers {
		p.closeAll()
	}
	wg.Wait()
	return runErr
}

// tunReader reads packets from the TUN and sends each to the peer routing its
// destination, until the device is closed.
func (n *Node) tunReader() {
	buf := make([]byte, 65535)
	for {
		m, err := n.dev.Read(buf)
		if err != nil {
			return // device closed on shutdown
		}
		pkt := buf[:m]
		if ipx.Version(pkt) == 4 && m >= 20 {
			if p, ok := n.routes.Lookup([4]byte(pkt[16:20])); ok {
				if n.flows != nil {
					n.flows.Seen(pkt, "via "+p.name)
				}
				p.send(append([]byte(nil), pkt...), n.tunIP)
				continue
			}
		}
		// Not routed to any peer: blocked. Answer so the sender fails fast.
		if r := ipx.Reject(pkt); r != nil {
			if n.flows != nil {
				n.flows.Blocked(pkt)
			}
			_, _ = n.dev.Write(r)
		}
	}
}

// deliver writes a packet received from a peer to the TUN. Its source must be
// routed to that peer, so a peer cannot inject traffic posing as another
// peer's (or unrouted) addresses. ICMP errors are exempt -- they come from
// routers along the path (path-MTU discovery needs them).
func (n *Node) deliver(l *link, pkt []byte) {
	if ipx.Version(pkt) != 4 || len(pkt) < 20 {
		return
	}
	if l.localIP != 0 {
		ipx.RewriteDst4(pkt, ip4(l.localIP), n.tunIP)
	}
	if l.p.nat != nil {
		l.p.nat.In(pkt)
	}
	if owner, ok := n.routes.Lookup([4]byte(pkt[12:16])); !(ok && owner == l.p) && !ipx.IsICMPv4Error(pkt) {
		return
	}
	ipx.ClampMSS(pkt, l.mss)
	if n.flows != nil {
		n.flows.Seen(pkt, "from "+l.p.name)
	}
	if _, err := n.dev.Write(pkt); err != nil {
		log.Printf("[%s] tun write: %v", l.p.name, err)
	}
}

// housekeeping drops idle NAT mappings and logged flows until quit is closed.
func (n *Node) housekeeping(quit <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-quit:
			return
		case <-t.C:
			for _, p := range n.peers {
				if p.nat != nil {
					p.nat.Expire()
				}
			}
			if n.flows != nil {
				n.flows.Expire()
			}
		}
	}
}

func u32(a [4]byte) uint32 {
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}

func ip4(v uint32) [4]byte {
	return [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}
