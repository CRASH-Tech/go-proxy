// Package client implements the client role. It maintains one tunnel per
// configured server, each capturing IP packets from its own TUN device and
// relaying them through an authenticated, encrypted session; per-server routes
// decide which traffic goes through which server.
package client

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"goproxy/internal/config"
	"goproxy/internal/keys"
	"goproxy/internal/netsetup"
	"goproxy/internal/noise"
	"goproxy/internal/protocol"
	"goproxy/internal/transport"
	"goproxy/internal/tun"
)

// Client runs one tunnel per configured server.
type Client struct {
	tunnels []*tunnel
}

// New builds a Client (and its per-server tunnels) from configuration.
func New(cfg *config.ClientConfig) (*Client, error) {
	c := &Client{}
	for i := range cfg.Servers {
		t, err := newTunnel(&cfg.Servers[i], cfg)
		if err != nil {
			return nil, fmt.Errorf("server %q: %w", cfg.Servers[i].Name, err)
		}
		c.tunnels = append(c.tunnels, t)
	}
	return c, nil
}

// Run starts every tunnel and blocks until stop is closed (or all tunnels exit).
// It returns the first fatal error a tunnel reported.
func (c *Client) Run(stop <-chan struct{}) error {
	errs := make([]error, len(c.tunnels))
	var wg sync.WaitGroup
	for i, t := range c.tunnels {
		wg.Add(1)
		go func(i int, t *tunnel) {
			defer wg.Done()
			if err := t.run(stop); err != nil {
				log.Printf("tunnel %q: %v", t.name, err)
				errs[i] = err
			}
		}(i, t)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// tunnel maintains a single server connection: its own TUN device, reconnect
// loop and routes.
type tunnel struct {
	name       string
	sc         *config.ServerConn
	priv       keys.PrivateKey
	serverPub  keys.PublicKey
	psk        [32]byte
	tr         transport.Transport // nil for udp
	mtu        int
	obfsMaxPad int
	obfsCover  bool

	dev        *tun.Device
	configured bool
	cleanup    *netsetup.Cleanup
}

func newTunnel(sc *config.ServerConn, cfg *config.ClientConfig) (*tunnel, error) {
	priv, err := sc.ParsePrivateKey()
	if err != nil {
		return nil, err
	}
	pub, err := sc.ParseServerPublicKey()
	if err != nil {
		return nil, err
	}
	t := &tunnel{
		name:       sc.Name,
		sc:         sc,
		priv:       priv,
		serverPub:  pub,
		psk:        config.DerivePSK(sc.PSK),
		mtu:        cfg.MTU,
		obfsMaxPad: cfg.ObfsMaxPad,
		obfsCover:  cfg.ObfsCover,
		cleanup:    &netsetup.Cleanup{},
	}
	switch sc.Transport {
	case "aead":
		t.tr = transport.NewTCP()
	case "tls":
		t.tr = transport.NewTLSClient(sc.TLS.SNI, sc.TLS.Insecure)
	case "udp":
		// datagram session, no stream transport
	default:
		return nil, fmt.Errorf("unknown transport %q", sc.Transport)
	}
	return t, nil
}

// run opens the TUN device and maintains the tunnel, reconnecting on failure,
// until stop is closed.
func (t *tunnel) run(stop <-chan struct{}) error {
	dev, err := tun.Open(t.sc.InterfaceName)
	if err != nil {
		return err
	}
	t.dev = dev
	log.Printf("[%s] tun device %s up", t.name, dev.Name())

	defer func() {
		t.cleanup.Run()
		dev.Close()
	}()

	outCh := make(chan []byte, 512)
	go t.tunReader(outCh)

	backoff := time.Second
	for {
		select {
		case <-stop:
			return nil
		default:
		}

		sess, hello, remoteIP, err := t.connect()
		if err != nil {
			log.Printf("[%s] connect failed: %v (retrying in %s)", t.name, err, backoff)
			if sleep(stop, backoff) {
				return nil
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = time.Second

		if !t.configured {
			if err := t.setup(hello, remoteIP); err != nil {
				sess.Close()
				return fmt.Errorf("setup: %w", err)
			}
			t.configured = true
			log.Printf("[%s] tunnel established: %s via %s (server %s)", t.name, hello.ClientIP, remoteIP, hello.ServerIP)
		} else {
			log.Printf("[%s] reconnected: %s", t.name, hello.ClientIP)
		}

		t.runSession(sess, outCh, stop)

		select {
		case <-stop:
			return nil
		default:
			if sleep(stop, time.Second) {
				return nil
			}
		}
	}
}

// tunReader continuously reads packets from the TUN device and pushes copies
// into outCh. If no session is draining outCh, packets are dropped.
func (t *tunnel) tunReader(outCh chan<- []byte) {
	buf := make([]byte, 65535)
	for {
		n, err := t.dev.Read(buf)
		if err != nil {
			return // device closed on shutdown
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case outCh <- pkt:
		default:
			// Backpressure: drop rather than stall the reader.
		}
	}
}

func (t *tunnel) connect() (noise.Tunnel, *protocol.ServerHello, net.IP, error) {
	hello := protocol.NewClientHello(hostname())

	var conn net.Conn
	var err error
	if t.sc.Transport == "udp" {
		conn, err = net.Dial("udp", t.sc.Address)
	} else {
		conn, err = t.tr.Dial(t.sc.Address)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var sess noise.Tunnel
	var payload []byte
	if t.sc.Transport == "udp" {
		sess, payload, err = noise.InitiatePacket(conn, t.priv, t.serverPub, t.psk, hello.Marshal())
	} else {
		sess, payload, err = noise.Initiate(conn, t.priv, t.serverPub, t.psk, hello.Marshal())
	}
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	_ = conn.SetDeadline(time.Time{})

	sh, err := protocol.ParseServerHello(payload)
	if err != nil {
		sess.Close()
		return nil, nil, nil, err
	}
	return sess, sh, addrIP(conn.RemoteAddr()), nil
}

// setup configures the TUN address and host routing/NAT after the first
// successful handshake.
func (t *tunnel) setup(hello *protocol.ServerHello, remoteIP net.IP) error {
	_, subnet, err := net.ParseCIDR(hello.Subnet)
	if err != nil {
		return fmt.Errorf("server subnet %q: %w", hello.Subnet, err)
	}
	prefix, _ := subnet.Mask.Size()
	mtu := hello.MTU
	if mtu == 0 {
		mtu = t.mtu
	}
	cidr := fmt.Sprintf("%s/%d", hello.ClientIP, prefix)
	if err := t.dev.Configure(cidr, mtu); err != nil {
		return err
	}

	// Keep the encrypted tunnel connection itself off the tunnel. DefaultRoute
	// reads the 0.0.0.0/0 default, which SetDefaultViaTunnel does not touch, so
	// this stays correct even when another tunnel has taken the default.
	if remoteIP != nil {
		gw, iface, err := netsetup.DefaultRoute()
		if err == nil {
			if err := netsetup.PinServerRoute(t.cleanup, remoteIP.String(), gw, iface); err != nil {
				log.Printf("[%s] warning: pin server route: %v", t.name, err)
			}
		} else {
			log.Printf("[%s] warning: default route lookup: %v", t.name, err)
		}
	}

	if t.sc.Gateway {
		if err := netsetup.ClientGatewayNAT(t.cleanup, t.dev.Name()); err != nil {
			return fmt.Errorf("gateway NAT: %w", err)
		}
		log.Printf("[%s] gateway mode: forwarded traffic masqueraded into %s", t.name, t.dev.Name())
	}
	if t.sc.SetDefaultRoute {
		if err := netsetup.SetDefaultViaTunnel(t.cleanup, hello.ServerIP, t.dev.Name()); err != nil {
			return fmt.Errorf("default route: %w", err)
		}
		log.Printf("[%s] default route now via tunnel gateway %s", t.name, hello.ServerIP)
	}
	if len(t.sc.Routes) > 0 {
		if err := netsetup.AddRoutes(t.cleanup, t.sc.Routes, hello.ServerIP, t.dev.Name()); err != nil {
			return fmt.Errorf("routes: %w", err)
		}
		log.Printf("[%s] split-tunnel: %d prefix(es) routed via %s dev %s",
			t.name, len(t.sc.Routes), hello.ServerIP, t.dev.Name())
	}
	return nil
}

// runSession drives one connected session until it fails or stop is closed.
func (t *tunnel) runSession(sess noise.Tunnel, outCh <-chan []byte, stop <-chan struct{}) {
	defer sess.Close()
	sess.SetMaxPad(t.obfsMaxPad)

	var once sync.Once
	done := make(chan struct{})
	closeDone := func() { once.Do(func() { close(done) }) }

	// session -> TUN
	go func() {
		defer closeDone()
		for {
			pkt, err := sess.ReadPacket()
			if err != nil {
				return
			}
			if _, err := t.dev.Write(pkt); err != nil {
				log.Printf("[%s] tun write: %v", t.name, err)
				return
			}
		}
	}()

	// cover traffic (also keeps NAT alive), or a plain keepalive when disabled.
	coverStop := make(chan struct{})
	defer close(coverStop)
	ka := time.Duration(t.sc.KeepaliveSec) * time.Second
	if t.obfsCover {
		go sess.RunCover(ka, noise.CoverMaxJunk, coverStop)
	} else {
		go plainKeepalive(sess, ka, coverStop)
	}

	// TUN -> session
	for {
		select {
		case <-stop:
			return
		case <-done:
			return
		case pkt := <-outCh:
			if err := sess.WritePacket(pkt); err != nil {
				return
			}
		}
	}
}

// plainKeepalive sends a fixed-interval keepalive (used when cover traffic is off).
func plainKeepalive(sess noise.Tunnel, interval time.Duration, stop <-chan struct{}) {
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

func nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// sleep waits for d or until stop is closed; returns true if stopped.
func sleep(stop <-chan struct{}, d time.Duration) bool {
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-stop:
		return true
	case <-tm.C:
		return false
	}
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "client"
	}
	return h
}

func addrIP(a net.Addr) net.IP {
	if a == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
