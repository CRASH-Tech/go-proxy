// Package server implements the server role: it terminates client tunnels,
// authenticates them, and forwards their traffic to the internet via a TUN
// device plus kernel NAT.
package server

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"goproxy/internal/config"
	"goproxy/internal/fallback"
	"goproxy/internal/ipx"
	"goproxy/internal/keys"
	"goproxy/internal/netsetup"
	"goproxy/internal/noise"
	"goproxy/internal/protocol"
	"goproxy/internal/transport"
	"goproxy/internal/tun"
)

type authEntry struct {
	entry   config.ClientEntry
	ip      net.IP
	allowed []*net.IPNet
}

type clientConn struct {
	sess    *noise.Session
	name    string
	ip      net.IP
	allowed []*net.IPNet
}

func (c *clientConn) allows(ip net.IP) bool {
	for _, n := range c.allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Server is the running server instance.
type Server struct {
	cfg   *config.ServerConfig
	priv  keys.PrivateKey
	psk   [32]byte
	allow map[keys.PublicKey]authEntry
	fb    *fallback.Handler

	dev *tun.Device
	tr  transport.Transport
	ln  net.Listener
	udp *net.UDPConn

	mu        sync.RWMutex
	clients   map[string]*clientConn // key: assigned tunnel IP string
	udpByAddr map[string]*udpClient  // key: remote UDP addr string
	udpByIP   map[string]*udpClient  // key: assigned tunnel IP string
}

// Close stops the server: it closes the listener and TUN device so Run returns
// and its deferred cleanup (NAT rules) executes.
func (s *Server) Close() {
	if s.ln != nil {
		s.ln.Close()
	}
	if s.udp != nil {
		s.udp.Close()
	}
	if s.dev != nil {
		s.dev.Close()
	}
}

// New builds a Server from configuration.
func New(cfg *config.ServerConfig) (*Server, error) {
	priv, err := cfg.ParsePrivateKey()
	if err != nil {
		return nil, err
	}
	fb, err := fallback.New(cfg.FallbackMode, cfg.FallbackStatus, cfg.FallbackURL, cfg.FallbackTarget)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:     cfg,
		priv:    priv,
		psk:     config.DerivePSK(cfg.PSK),
		allow:     make(map[keys.PublicKey]authEntry),
		clients:   make(map[string]*clientConn),
		udpByAddr: make(map[string]*udpClient),
		udpByIP:   make(map[string]*udpClient),
		fb:        fb,
	}
	for _, cl := range cfg.Clients {
		pub, err := keys.ParsePublicKey(cl.PublicKey)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(cl.IP)
		if ip == nil {
			return nil, fmt.Errorf("client %q: bad ip %q", cl.Name, cl.IP)
		}
		allowed := []*net.IPNet{{IP: ip, Mask: fullMask(ip)}}
		for _, cidr := range cl.AllowedIPs {
			_, n, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("client %q: bad allowed_ip %q: %w", cl.Name, cidr, err)
			}
			allowed = append(allowed, n)
		}
		s.allow[pub] = authEntry{entry: cl, ip: ip, allowed: allowed}
	}
	return s, nil
}

func fullMask(ip net.IP) net.IPMask {
	if ip.To4() != nil {
		return net.CIDRMask(32, 32)
	}
	return net.CIDRMask(128, 128)
}

// Run sets up the TUN device and NAT, then serves clients until an error occurs.
func (s *Server) Run() error {
	// TUN device.
	dev, err := tun.Open(s.cfg.InterfaceName)
	if err != nil {
		return err
	}
	s.dev = dev
	log.Printf("tun device %s up", dev.Name())

	_, subnet, err := net.ParseCIDR(s.cfg.Tunnel.Subnet)
	if err != nil {
		return fmt.Errorf("tunnel subnet: %w", err)
	}
	prefix, _ := subnet.Mask.Size()
	serverCIDR := fmt.Sprintf("%s/%d", s.cfg.Tunnel.ServerIP, prefix)
	if err := dev.Configure(serverCIDR, s.cfg.MTU); err != nil {
		return err
	}

	// NAT / forwarding.
	cleanup := &netsetup.Cleanup{}
	defer cleanup.Run()
	if s.cfg.AutoNAT {
		egress := s.cfg.EgressInterface
		if egress == "" {
			_, egress, err = netsetup.DefaultRoute()
			if err != nil {
				return fmt.Errorf("autodetect egress: %w (set egress_interface)", err)
			}
		}
		if err := netsetup.ServerNAT(cleanup, s.cfg.Tunnel.Subnet, egress); err != nil {
			return fmt.Errorf("setup NAT: %w", err)
		}
		log.Printf("NAT enabled: %s -> %s (masquerade)", s.cfg.Tunnel.Subnet, egress)
	}

	// UDP uses a datagram datapath instead of the stream listener/accept model.
	if s.cfg.Transport == "udp" {
		return s.runUDP()
	}

	// Transport.
	s.tr, err = s.buildTransport()
	if err != nil {
		return err
	}
	ln, err := s.tr.Listen(s.cfg.Listen)
	if err != nil {
		return err
	}
	s.ln = ln
	defer ln.Close()
	log.Printf("listening on %s (%s)", s.cfg.Listen, s.cfg.Transport)

	// TUN -> clients (return traffic from the internet).
	go s.tunToClients()

	// Accept loop.
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) buildTransport() (transport.Transport, error) {
	switch s.cfg.Transport {
	case "aead":
		return transport.NewTCP(), nil
	case "tls":
		cert, err := transport.LoadOrCreateCert(s.cfg.TLS.Cert, s.cfg.TLS.Key, s.cfg.TLS.Host)
		if err != nil {
			return nil, fmt.Errorf("tls cert: %w", err)
		}
		return transport.NewTLSServer(cert), nil
	default:
		return nil, fmt.Errorf("unknown transport %q", s.cfg.Transport)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr()

	// Bound the handshake in time.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var matched authEntry
	auth := func(pub keys.PublicKey) (psk [32]byte, response []byte, ok bool) {
		e, found := s.allow[pub]
		if !found {
			return psk, nil, false
		}
		matched = e
		hello := protocol.NewServerHello(e.entry.IP, s.cfg.Tunnel.ServerIP, s.cfg.Tunnel.Subnet, s.cfg.MTU)
		return s.psk, hello.Marshal(), true
	}

	// Record the bytes consumed during the handshake so that, if it fails, we
	// can replay them to the fallback (e.g. a reverse-proxy backend).
	rec := &recorderConn{Conn: conn, recording: true}
	sess, remoteStatic, payload1, err := noise.Respond(rec, s.priv, auth)
	rec.recording = false
	if err != nil {
		if s.fb != nil {
			_ = conn.SetDeadline(time.Time{})
			log.Printf("unauthenticated connection from %s -> fallback (%s)", remote, s.fb.Describe())
			s.fb.Serve(newReplayConn(conn, rec.buf))
			return
		}
		log.Printf("handshake from %s failed: %v", remote, err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	hello, err := protocol.ParseClientHello(payload1)
	if err != nil {
		log.Printf("client %s: bad hello: %v", remote, err)
		return
	}
	if err := hello.Validate(); err != nil {
		log.Printf("client %s: %v", remote, err)
		return
	}

	name := matched.entry.Name
	if name == "" {
		name = keys.PublicKey(remoteStatic).String()
	}
	cc := &clientConn{sess: sess, name: name, ip: matched.ip, allowed: matched.allowed}
	sess.MaxPad = s.cfg.ObfsMaxPad
	sess.SetMaxPayload(s.cfg.MTU)

	// Symmetric cover traffic from the server side.
	if s.cfg.ObfsCover {
		coverStop := make(chan struct{})
		defer close(coverStop)
		go sess.RunCover(25*time.Second, noise.CoverMaxJunk, coverStop)
	}

	key := matched.ip.String()
	s.mu.Lock()
	if old := s.clients[key]; old != nil {
		old.sess.Close()
	}
	s.clients[key] = cc
	s.mu.Unlock()
	log.Printf("client %q connected from %s as %s", name, remote, matched.ip)

	defer func() {
		s.mu.Lock()
		if s.clients[key] == cc {
			delete(s.clients, key)
		}
		s.mu.Unlock()
		log.Printf("client %q (%s) disconnected", name, matched.ip)
	}()

	// clients -> TUN (outbound to the internet).
	for {
		pkt, err := sess.ReadPacket()
		if err != nil {
			return
		}
		src := ipx.SrcIP(pkt)
		if src == nil || !cc.allows(src) {
			// Anti-spoofing: drop packets whose source is not routed to this client.
			continue
		}
		if _, err := s.dev.Write(pkt); err != nil {
			log.Printf("tun write: %v", err)
			return
		}
	}
}

func (s *Server) tunToClients() {
	buf := make([]byte, 65535)
	for {
		n, err := s.dev.Read(buf)
		if err != nil {
			log.Printf("tun read: %v", err)
			return
		}
		pkt := buf[:n]
		dst := ipx.DstIP(pkt)
		if dst == nil {
			continue
		}
		cc := s.route(dst)
		if cc == nil {
			continue
		}
		if err := cc.sess.WritePacket(pkt); err != nil {
			// The client's read loop will clean up on its own.
			continue
		}
	}
}

// recorderConn tees everything read from the underlying connection into buf
// while recording is true, so the bytes consumed by a failed handshake can be
// replayed to the fallback handler.
type recorderConn struct {
	net.Conn
	buf       []byte
	recording bool
}

func (r *recorderConn) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 && r.recording {
		r.buf = append(r.buf, p[:n]...)
	}
	return n, err
}

// replayConn presents a connection whose reads yield prefix first (the bytes
// already consumed during the handshake) and then the live stream. Writes,
// deadlines and Close go to the underlying connection.
type replayConn struct {
	net.Conn
	r io.Reader
}

func newReplayConn(c net.Conn, prefix []byte) *replayConn {
	return &replayConn{Conn: c, r: io.MultiReader(bytes.NewReader(prefix), c)}
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (s *Server) route(dst net.IP) *clientConn {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Fast path: exact assigned IP.
	if cc := s.clients[dst.String()]; cc != nil {
		return cc
	}
	// Slow path: match extra allowed_ips.
	for _, cc := range s.clients {
		if cc.allows(dst) {
			return cc
		}
	}
	return nil
}
