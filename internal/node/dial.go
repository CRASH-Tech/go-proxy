package node

import (
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"goproxy/internal/noise"
	"goproxy/internal/protocol"
	"goproxy/internal/transport"
)

// dialLoop keeps an outbound session to p, reconnecting on failure, until quit
// is closed.
func (n *Node) dialLoop(p *peer, quit <-chan struct{}) {
	backoff := time.Second
	connected := false
	for {
		select {
		case <-quit:
			return
		default:
		}

		sess, hello, err := n.connect(p)
		if err != nil {
			log.Printf("[%s] connect to %s failed: %v (retrying in %s)", p.name, p.cfg.Endpoint, err, backoff)
			if sleep(quit, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = time.Second

		var localIP uint32
		if hello.ClientIP != "" {
			ip, err := netip.ParseAddr(hello.ClientIP)
			if err != nil || !ip.Is4() {
				log.Printf("[%s] peer assigned a bad tunnel IP %q", p.name, hello.ClientIP)
				sess.Close()
				if sleep(quit, 30*time.Second) {
					return
				}
				continue
			}
			localIP = u32(ip.As4())
		}
		mtu := hello.MTU
		if mtu == 0 {
			mtu = n.cfg.MTU
		}

		l := n.newLink(p, true, sess, mtu)
		l.localIP = localIP
		l.closeFn = func() { sess.Close() }
		p.attach(l)
		n.startLink(l)

		as := "addresses kept"
		if localIP != 0 {
			as = "tunnel IP " + hello.ClientIP
		}
		if !connected {
			log.Printf("[%s] connected to %s (%s)", p.name, p.cfg.Endpoint, as)
			if mtu < n.cfg.MTU {
				log.Printf("[%s] warning: peer MTU %d < GOPROXY_MTU %d; lower GOPROXY_MTU if large packets stall",
					p.name, mtu, n.cfg.MTU)
			}
			connected = true
		} else {
			log.Printf("[%s] reconnected to %s (%s)", p.name, p.cfg.Endpoint, as)
		}

		for {
			pkt, err := sess.ReadPacket()
			if err != nil {
				break
			}
			n.deliver(l, pkt)
		}
		l.close()

		if sleep(quit, time.Second) {
			return
		}
	}
}

// connect opens the transport to p's endpoint and runs the initiator handshake.
func (n *Node) connect(p *peer) (noise.Tunnel, *protocol.ServerHello, error) {
	hello := protocol.NewClientHello(hostname())

	var conn net.Conn
	var err error
	if p.cfg.Transport == "udp" {
		conn, err = transport.ClientDialer("udp", n.cfg.FwMark).Dial("udp", p.cfg.Endpoint)
	} else {
		conn, err = p.tr.Dial(p.cfg.Endpoint)
	}
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var sess noise.Tunnel
	var payload []byte
	if p.cfg.Transport == "udp" {
		sess, payload, err = noise.InitiatePacket(conn, n.priv, p.pub, p.psk, hello.Marshal())
	} else {
		sess, payload, err = noise.Initiate(conn, n.priv, p.pub, p.psk, hello.Marshal())
	}
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Time{})

	sh, err := protocol.ParseServerHello(payload)
	if err != nil {
		sess.Close()
		return nil, nil, err
	}
	return sess, sh, nil
}

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// sleep waits for d or until quit is closed; returns true if quit.
func sleep(quit <-chan struct{}, d time.Duration) bool {
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-quit:
		return true
	case <-tm.C:
		return false
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "node"
	}
	return h
}
