package server

import (
	"context"
	"log"
	"net"
	"sync/atomic"
	"time"

	"goproxy/internal/ipx"
	"goproxy/internal/keys"
	"goproxy/internal/noise"
	"goproxy/internal/protocol"
	"goproxy/internal/sockopt"
)

// minHandshakeMsg is the smallest possible message-1 (e + encStatic + empty
// encPayload). Datagrams smaller than this are never handshakes.
const minHandshakeMsg = 32 + 32 + 16 + 16

// udpIdleTimeout removes a UDP client that has sent nothing (not even cover
// traffic) for this long.
const udpIdleTimeout = 150 * time.Second

type udpClient struct {
	ps       *noise.PacketSession
	name     string
	ip       net.IP
	allowed  []*net.IPNet
	addr     *net.UDPAddr
	lastSeen atomic.Int64 // unix nanos
	stop     chan struct{}
}

func (u *udpClient) allows(ip net.IP) bool {
	for _, n := range u.allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// runUDP serves the datagram (UDP) transport: a single socket that demuxes
// datagrams by source address to per-client datagram sessions.
func (s *Server) runUDP() error {
	lc := net.ListenConfig{Control: sockopt.UDPControl}
	packetConn, err := lc.ListenPacket(context.Background(), "udp", s.cfg.Listen)
	if err != nil {
		return err
	}
	pc := packetConn.(*net.UDPConn)
	s.udp = pc
	defer pc.Close()
	log.Printf("listening on %s (udp)", s.cfg.Listen)

	go s.tunToClientsUDP()
	go s.reapUDP()

	buf := make([]byte, 65535)
	for {
		n, raddr, err := pc.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		s.handleUDPDatagram(raddr, buf[:n])
	}
}

func (s *Server) handleUDPDatagram(addr *net.UDPAddr, datagram []byte) {
	key := addr.String()
	s.mu.RLock()
	uc := s.udpByAddr[key]
	s.mu.RUnlock()

	if uc != nil {
		pkt, ok, err := uc.ps.OpenPacket(datagram)
		if err == nil {
			uc.lastSeen.Store(time.Now().UnixNano())
			if ok {
				src := ipx.SrcIP(pkt)
				if src == nil || !uc.allows(src) {
					return // anti-spoofing
				}
				if _, werr := s.dev.Write(pkt); werr != nil {
					log.Printf("tun write: %v", werr)
				}
			}
			return
		}
		// Decryption failed. If it is large enough to be a handshake, the client
		// may have reconnected from the same address; fall through. Otherwise drop.
		if len(datagram) < minHandshakeMsg {
			return
		}
	}

	// New peer (or reconnect): treat the datagram as handshake message 1.
	msg := append([]byte(nil), datagram...)
	s.handleUDPHandshake(addr, msg)
}

func (s *Server) handleUDPHandshake(addr *net.UDPAddr, msg1 []byte) {
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
	write := func(b []byte) error {
		_, e := s.udp.WriteToUDP(b, addr)
		return e
	}

	ps, remoteStatic, payload1, err := noise.RespondPacket(msg1, s.priv, auth, write)
	if err != nil {
		// Probe/scanner or unauthorized; drop silently.
		return
	}
	hello, err := protocol.ParseClientHello(payload1)
	if err != nil || hello.Validate() != nil {
		return
	}
	ps.SetMaxPad(s.cfg.ObfsMaxPad)
	ps.SetMaxPayload(s.cfg.MTU)

	name := matched.entry.Name
	if name == "" {
		name = keys.PublicKey(remoteStatic).String()
	}
	uc := &udpClient{ps: ps, name: name, ip: matched.ip, allowed: matched.allowed, addr: addr, stop: make(chan struct{})}
	uc.lastSeen.Store(time.Now().UnixNano())

	ipKey := matched.ip.String()
	s.mu.Lock()
	if old := s.udpByIP[ipKey]; old != nil {
		delete(s.udpByAddr, old.addr.String())
		close(old.stop)
	}
	if old := s.udpByAddr[addr.String()]; old != nil && old != uc {
		close(old.stop)
	}
	s.udpByAddr[addr.String()] = uc
	s.udpByIP[ipKey] = uc
	s.mu.Unlock()
	log.Printf("client %q connected from %s as %s (udp)", name, addr, matched.ip)

	if s.cfg.ObfsCover {
		go ps.RunCover(25*time.Second, noise.CoverMaxJunk, uc.stop)
	}
}

func (s *Server) tunToClientsUDP() {
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
		uc := s.routeUDP(dst)
		if uc == nil {
			continue
		}
		if err := uc.ps.WritePacket(pkt); err != nil {
			continue
		}
	}
}

func (s *Server) routeUDP(dst net.IP) *udpClient {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if uc := s.udpByIP[dst.String()]; uc != nil {
		return uc
	}
	for _, uc := range s.udpByIP {
		if uc.allows(dst) {
			return uc
		}
	}
	return nil
}

func (s *Server) reapUDP() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		now := time.Now().UnixNano()
		s.mu.Lock()
		for ip, uc := range s.udpByIP {
			if now-uc.lastSeen.Load() > int64(udpIdleTimeout) {
				delete(s.udpByIP, ip)
				delete(s.udpByAddr, uc.addr.String())
				close(uc.stop)
				log.Printf("client %q (%s) timed out (udp)", uc.name, uc.ip)
			}
		}
		s.mu.Unlock()
	}
}
