// Package node implements goproxy's only role. A node owns one TUN device and
// exchanges IP packets with its peers over encrypted, obfuscated sessions: it
// accepts peers that connect to it (GOPROXY_LISTEN) and connects to the peers
// that have an endpoint. Every packet read from the TUN goes to the peer whose
// routes contain its destination (longest prefix wins); packets no peer routes
// are blocked. Which traffic reaches the TUN is up to the host's routes -- set
// by the admin, or pushed from the peers' routes with GOPROXY_PUSH_ROUTES.
// A peer may instead have a TUN of its own (Interface): a next hop for the
// host's routes, outside the node TUN's route table.
// NAT to the internet is the host's too, or GOPROXY_MASQUERADE; forwarding
// (ip_forward) is always the admin's.
//
// Peers come from the environment and, with a data directory, from the web
// UI; the set can change while the node runs (see SetFilePeers).
package node

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	tunIP  [4]byte
	tunNet string // the TUN's network, told to connecting peers
	fb     *fallback.Handler
	flows  *flowlog.Logger // nil unless GOPROXY_LOG_CONNECTIONS

	keyMu     sync.RWMutex
	priv      keys.PrivateKey
	keySource string // "env" or "file"

	set atomic.Pointer[peerSet] // the current (enabled) peers; replaced as a whole

	// OnStarted, if set, is called once Run has everything up (TUN, host
	// routes, listener), e.g. to confirm settings just changed.
	OnStarted func()

	mu        sync.Mutex // serialises changes of the peer set and start/stop
	filePeers []config.Peer
	running   bool
	stopped   bool // Run has returned: host routes are no longer managed
	dev       *tun.Device
	dials     sync.WaitGroup
	pushed    []netip.Prefix // prefixes currently pushed to the host
	unpush    func()
}

// peerSet is an immutable snapshot of the peers and their routes.
type peerSet struct {
	peers  []*peer
	byKey  map[keys.PublicKey]*peer
	byName map[string]*peer
	routes *route.Table[*peer]
}

// New builds a Node (its key, peers and route table) from configuration.
func New(cfg *config.NodeConfig) (*Node, error) {
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
		tunIP:  addr.Addr().As4(),
		tunNet: addr.Masked().String(),
		fb:     fb,
	}
	if cfg.LogConns {
		n.flows = flowlog.New(log.Printf)
	}

	if cfg.PrivateKey != "" {
		n.priv, err = cfg.ParsePrivateKey()
		n.keySource = "env"
	} else {
		var created bool
		n.priv, created, err = loadOrCreateKey(cfg.DataDir)
		n.keySource = "file"
		if created {
			log.Printf("generated this node's key in %s; public key %s", cfg.DataDir, n.priv.Public())
		}
	}
	if err != nil {
		return nil, err
	}

	if cfg.DataDir != "" {
		if n.filePeers, err = loadPeers(cfg.DataDir); err != nil {
			return nil, err
		}
	}
	set, _, err := n.buildSet(n.filePeers)
	if err != nil {
		return nil, err
	}
	n.set.Store(set)
	return n, nil
}

// buildSet makes the peer set for the environment's peers plus file (as
// stored, before defaults). A peer whose sessions stay valid (see
// sessionEqual) keeps its current object, and with it its sessions; any other
// change of its settings (routes, NAT, keepalive) is returned in apply, to be
// run once the set is committed.
func (n *Node) buildSet(file []config.Peer) (set *peerSet, apply []func(), err error) {
	type src struct {
		cfg    config.Peer
		source string
	}
	var all []src
	for _, p := range n.cfg.Peers {
		all = append(all, src{p, "env"})
	}
	for _, p := range file {
		n.cfg.ApplyDefaults(&p)
		all = append(all, src{p, "file"})
	}
	cfgs := make([]config.Peer, len(all))
	for i, s := range all {
		cfgs[i] = s.cfg
	}
	if err := config.ValidatePeers(cfgs); err != nil {
		return nil, nil, err
	}

	old := n.set.Load()
	set = &peerSet{
		byKey:  map[keys.PublicKey]*peer{},
		byName: map[string]*peer{},
		routes: &route.Table[*peer]{},
	}
	for _, s := range all {
		pc := s.cfg
		if pc.Disabled {
			continue
		}
		if pc.Interface != "" {
			if pc.Interface == n.cfg.InterfaceName {
				return nil, nil, fmt.Errorf("peer %q: interface %q is the node's TUN", pc.Name, pc.Interface)
			}
			if !ownsInterface(old, pc.Interface) {
				if _, err := net.InterfaceByName(pc.Interface); err == nil {
					return nil, nil, fmt.Errorf("peer %q: interface %q already exists on this host", pc.Name, pc.Interface)
				}
			}
		}
		var p *peer
		if old != nil {
			if op := old.byName[pc.Name]; op != nil && op.source == s.source && sessionEqual(op.conf(), &pc) {
				p = op
				if !reflect.DeepEqual(*op.conf(), pc) {
					apply = append(apply, func() { op.update(&pc, n.tunIP) })
				}
			}
		}
		if p == nil {
			if p, err = newPeer(&pc, n.cfg.FwMark, n.tunIP); err != nil {
				return nil, nil, fmt.Errorf("peer %q: %w", pc.Name, err)
			}
			p.source = s.source
		}
		prefixes, err := pc.Prefixes()
		if err != nil {
			return nil, nil, fmt.Errorf("peer %q: %w", p.name, err)
		}
		if pc.Interface != "" {
			prefixes = nil // reached through its own interface, not the route table
		}
		for _, pfx := range prefixes {
			if err := set.routes.Insert(pfx, p); err != nil {
				return nil, nil, fmt.Errorf("peer %q route: %w", p.name, err)
			}
		}
		set.peers = append(set.peers, p)
		set.byKey[p.pub] = p
		set.byName[p.name] = p
	}
	return set, apply, nil
}

// ownsInterface reports whether a peer of set has the interface name.
func ownsInterface(set *peerSet, name string) bool {
	if set == nil {
		return false
	}
	for _, p := range set.peers {
		if p.conf().Interface == name {
			return true
		}
	}
	return false
}

// privKey returns the node's current static private key.
func (n *Node) privKey() keys.PrivateKey {
	n.keyMu.RLock()
	defer n.keyMu.RUnlock()
	return n.priv
}

// Run opens and configures the TUN, starts the listener and the connections to
// peers, and blocks until stop is closed or the listener fails.
func (n *Node) Run(stop <-chan struct{}) error {
	dev, err := tun.Open(n.cfg.InterfaceName)
	if err != nil {
		return err
	}
	defer dev.Close()
	if err := dev.Configure(n.cfg.Address, n.cfg.MTU); err != nil {
		return err
	}
	log.Printf("tun %s up (%s, mtu %d); %d peer(s); destinations without a peer are blocked",
		dev.Name(), n.cfg.Address, n.cfg.MTU, len(n.set.Load().peers))

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

	n.mu.Lock()
	n.dev = dev
	if err := n.pushRoutes(n.set.Load()); err != nil {
		n.mu.Unlock()
		return fmt.Errorf("push routes: %w", err)
	}
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.stopped = true
		if n.unpush != nil {
			n.unpush()
			n.unpush, n.pushed = nil, nil
		}
	}()

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

	n.mu.Lock()
	n.running = true
	for _, p := range n.set.Load().peers {
		n.startPeer(p)
	}
	n.mu.Unlock()

	quit := make(chan struct{})
	go n.tunReader()
	go n.housekeeping(quit)
	if n.OnStarted != nil {
		n.OnStarted()
	}

	var runErr error
	select {
	case <-stop:
	case runErr = <-errc:
	}
	close(quit)
	closeListener()
	n.mu.Lock()
	n.running = false
	for _, p := range n.set.Load().peers {
		p.shutdown()
	}
	n.mu.Unlock()
	n.dials.Wait()
	return runErr
}

// startPeer creates p's own TUN, if it has one, and runs its outbound
// connection loop, if it has an endpoint. Called with n.mu held while running.
func (n *Node) startPeer(p *peer) {
	n.openInterface(p)
	if p.conf().Endpoint == "" {
		return
	}
	n.dials.Add(1)
	go func() {
		defer n.dials.Done()
		n.dialLoop(p)
	}()
}

// pushRoutes brings the host routes in line with set (GOPROXY_PUSH_ROUTES),
// replacing what was pushed before if the prefixes changed. Called with n.mu
// held.
func (n *Node) pushRoutes(set *peerSet) error {
	if n.cfg.PushRoutes == "false" || n.dev == nil || n.stopped {
		return nil
	}
	var prefixes []netip.Prefix
	for _, p := range set.peers {
		if p.conf().Interface != "" {
			continue // routed into its own interface by the admin
		}
		pfx, _ := p.conf().Prefixes() // validated when the set was built
		prefixes = append(prefixes, pfx...)
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	if n.unpush != nil && slices.Equal(prefixes, n.pushed) {
		return nil
	}
	if n.unpush != nil {
		n.unpush()
		n.unpush, n.pushed = nil, nil
	}
	warn := func(msg string) { log.Printf("push routes: warning: %s", msg) }
	scope, whom := hostroute.All, "host and clients"
	if n.cfg.PushRoutes == "clients" {
		scope, whom = hostroute.Clients, "clients only"
	}
	unpush, err := hostroute.Push(scope, n.dev.Name(), n.cfg.FwMark, prefixes, warn)
	if err != nil {
		return err
	}
	n.unpush, n.pushed = unpush, prefixes
	log.Printf("pushed the peers' %d route(s) into %s (%s)", len(prefixes), n.dev.Name(), whom)
	return nil
}

// SetFilePeers replaces the peers kept in the data directory: it validates
// them together with the environment's, saves them, and applies the change
// at once. Unchanged peers keep their sessions; removed or changed ones are
// disconnected (a changed one reconnects with its new settings).
func (n *Node) SetFilePeers(file []config.Peer) error {
	if n.cfg.DataDir == "" {
		return fmt.Errorf("peers can only be changed with GOPROXY_DATA_DIR set")
	}
	n.mu.Lock()
	defer n.mu.Unlock()

	set, apply, err := n.buildSet(file)
	if err != nil {
		return err
	}
	if err := savePeers(n.cfg.DataDir, file); err != nil {
		return err
	}
	old := n.set.Swap(set)
	for _, f := range apply {
		f()
	}
	n.filePeers = slices.Clone(file)

	for _, p := range old.peers {
		if set.byName[p.name] != p {
			p.shutdown()
		}
	}
	if n.running {
		for _, p := range set.peers {
			if old.byName[p.name] != p {
				n.startPeer(p)
			}
		}
	}
	log.Printf("peers updated: %d from the environment, %d from %s", len(n.cfg.Peers), len(file), n.cfg.DataDir)
	if err := n.pushRoutes(set); err != nil {
		return fmt.Errorf("peers applied, but pushing their routes failed: %w", err)
	}
	return nil
}

// tunReader reads packets from the TUN and sends each to the peer routing its
// destination, until the device is closed.
func (n *Node) tunReader() {
	n.mu.Lock()
	dev := n.dev
	n.mu.Unlock()
	buf := make([]byte, 65535)
	for {
		m, err := dev.Read(buf)
		if err != nil {
			if !errors.Is(err, os.ErrClosed) {
				log.Printf("tun read: %v", err)
			}
			return // device closed on shutdown
		}
		pkt := buf[:m]
		if ipx.Version(pkt) == 4 && m >= 20 {
			if p, ok := n.set.Load().routes.Lookup([4]byte(pkt[16:20])); ok {
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
			_, _ = dev.Write(r)
		}
	}
}

// openInterface creates and brings up p's own TUN (Interface), without an
// address, and starts reading it. A failure is logged; the peer then works
// without it (its packets are dropped). Called with n.mu held while running.
func (n *Node) openInterface(p *peer) {
	name := p.conf().Interface
	if name == "" || p.stopped() {
		return
	}
	dev, err := tun.Open(name)
	if err == nil {
		if err = dev.Configure("", n.cfg.MTU); err != nil {
			dev.Close()
		}
	}
	if err != nil {
		log.Printf("[%s] interface %s: %v", p.name, name, err)
		return
	}
	p.dev.Store(dev)
	log.Printf("[%s] tun %s up (mtu %d): traffic routed into it goes to the peer", p.name, dev.Name(), n.cfg.MTU)
	go n.interfaceReader(p, dev)
}

// interfaceReader sends every packet read from p's own TUN to p, whatever its
// destination (the host chose this interface), until the device is closed.
func (n *Node) interfaceReader(p *peer, dev *tun.Device) {
	buf := make([]byte, 65535)
	for {
		m, err := dev.Read(buf)
		if err != nil {
			if !errors.Is(err, os.ErrClosed) {
				log.Printf("[%s] tun %s read: %v", p.name, dev.Name(), err)
			}
			return
		}
		pkt := buf[:m]
		if ipx.Version(pkt) != 4 || m < 20 {
			continue // IPv6 (e.g. router solicitations): not carried
		}
		if n.flows != nil {
			n.flows.Seen(pkt, "via "+p.name)
		}
		p.send(append([]byte(nil), pkt...), n.tunIP)
	}
}

// deliver writes a packet received from a peer to the TUN -- the peer's own,
// if it has one. Its source must be routed to that peer (for a peer with an
// interface: be one of its routes), so a peer cannot inject traffic posing as
// another peer's (or unrouted) addresses. ICMP errors are exempt -- they come
// from routers along the path (path-MTU discovery needs them).
func (n *Node) deliver(l *link, pkt []byte) {
	if ipx.Version(pkt) != 4 || len(pkt) < 20 {
		return
	}
	l.rx.Add(uint64(len(pkt)))
	l.lastRx.Store(time.Now().UnixNano())
	if l.localIP != 0 {
		ipx.RewriteDst4(pkt, ip4(l.localIP), n.tunIP)
	}
	if nt := l.p.natTable(); nt != nil {
		nt.In(pkt)
	}
	src := [4]byte(pkt[12:16])
	dev := n.dev
	if l.p.conf().Interface != "" {
		if dev = l.p.device(); dev == nil {
			return // the interface could not be created (logged)
		}
		if !l.p.accepts(src) && !ipx.IsICMPv4Error(pkt) {
			return
		}
	} else if owner, ok := n.set.Load().routes.Lookup(src); !(ok && owner == l.p) && !ipx.IsICMPv4Error(pkt) {
		return
	}
	ipx.ClampMSS(pkt, l.mss)
	if n.flows != nil {
		n.flows.Seen(pkt, "from "+l.p.name)
	}
	if _, err := dev.Write(pkt); err != nil && !errors.Is(err, os.ErrClosed) {
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
			for _, p := range n.set.Load().peers {
				if nt := p.natTable(); nt != nil {
					nt.Expire()
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
