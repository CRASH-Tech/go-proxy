package node

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"goproxy/internal/keys"
	"goproxy/internal/noise"
	"goproxy/internal/protocol"
	"goproxy/internal/transport"
)

// authorizer admits configured peers by public key; the chosen peer is stored
// in *matched. The response tells the peer the tunnel IP it is handed (if any)
// and this node's TUN address.
func (n *Node) authorizer(matched **peer) noise.Authorizer {
	return func(pub keys.PublicKey) (psk [32]byte, response []byte, ok bool) {
		p := n.byKey[pub]
		if p == nil {
			return psk, nil, false
		}
		*matched = p
		tunIP := net.IP(n.tunIP[:]).String()
		hello := protocol.NewServerHello(p.cfg.IP, tunIP, n.tunNet, n.cfg.MTU)
		return p.psk, hello.Marshal(), true
	}
}

// listenStream accepts peers over the aead or tls transport. Accept errors are
// reported on errc; the returned func closes the listener.
func (n *Node) listenStream(errc chan<- error) (func(), error) {
	var tr transport.Transport
	switch n.cfg.Transport {
	case "aead":
		tr = transport.NewTCP()
	case "tls":
		cert, err := transport.LoadOrCreateCert(n.cfg.TLS.Cert, n.cfg.TLS.Key, n.cfg.TLS.Host)
		if err != nil {
			return nil, fmt.Errorf("tls cert: %w", err)
		}
		tr = transport.NewTLSServer(cert)
	default:
		return nil, fmt.Errorf("unknown transport %q", n.cfg.Transport)
	}
	ln, err := tr.Listen(n.cfg.Listen)
	if err != nil {
		return nil, err
	}
	log.Printf("listening on %s (%s)", n.cfg.Listen, n.cfg.Transport)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case errc <- err:
				default:
				}
				return
			}
			go n.handleConn(conn)
		}
	}()
	return func() { ln.Close() }, nil
}

// handleConn authenticates an incoming stream connection and serves it as the
// peer's inbound session; anything else is handed to the fallback.
func (n *Node) handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr()

	// Bound the handshake in time.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Record the bytes consumed during the handshake so that, if it fails, we
	// can replay them to the fallback (e.g. a reverse-proxy backend).
	var p *peer
	rec := &recorderConn{Conn: conn, recording: true}
	sess, _, payload1, err := noise.Respond(rec, n.priv, n.authorizer(&p))
	rec.recording = false
	if err != nil {
		if n.fb != nil {
			_ = conn.SetDeadline(time.Time{})
			log.Printf("unauthenticated connection from %s -> fallback (%s)", remote, n.fb.Describe())
			n.fb.Serve(newReplayConn(conn, rec.buf))
			return
		}
		log.Printf("handshake from %s failed: %v", remote, err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	if err := validHello(payload1); err != nil {
		log.Printf("[%s] from %s: %v", p.name, remote, err)
		return
	}

	l := n.newLink(p, false, sess, n.cfg.MTU)
	l.closeFn = func() { sess.Close() }
	p.attach(l)
	n.startLink(l)
	log.Printf("[%s] connected from %s", p.name, remote)

	for {
		pkt, err := sess.ReadPacket()
		if err != nil {
			break
		}
		n.deliver(l, pkt)
	}
	l.close()
	log.Printf("[%s] disconnected (%s)", p.name, remote)
}

// validHello checks the initiator's hello (timestamp anti-replay).
func validHello(payload []byte) error {
	hello, err := protocol.ParseClientHello(payload)
	if err != nil {
		return err
	}
	return hello.Validate()
}

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
