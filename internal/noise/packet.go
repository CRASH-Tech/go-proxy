package noise

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"goproxy/internal/keys"
)

var (
	errReplay = errors.New("noise: replayed or stale packet")
	errShort  = errors.New("noise: short datagram")
)

// Tunnel is the transport-agnostic view of an established session used by the
// client. Both the stream Session and the datagram PacketConn implement it.
type Tunnel interface {
	ReadPacket() ([]byte, error)
	WritePacket(pkt []byte) error
	WriteKeepalive() error
	WriteJunk(maxSize int) error
	RunCover(maxInterval time.Duration, maxJunk int, stop <-chan struct{})
	SetMaxPad(n int)
	SetMaxPayload(n int)
	Close() error
}

// SetMaxPad sets the maximum random padding per record.
func (s *Session) SetMaxPad(n int) { s.MaxPad = n }

func nonceFromCounter(ctr uint64) [nonceSize]byte {
	var n [nonceSize]byte
	binary.LittleEndian.PutUint64(n[4:], ctr)
	return n
}

// PacketSession carries IP packets over datagrams. Each datagram is
// counter(8 big-endian) || AEAD(payload) with the counter as the nonce, plus a
// receive-side anti-replay window. Unlike the stream Session it tolerates loss,
// reordering and duplication, so there is no head-of-line blocking.
type PacketSession struct {
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD

	sendMu  sync.Mutex
	sendCtr uint64

	replay     replayFilter
	MaxPad     int
	MaxPayload int

	send func([]byte) error // transmit one datagram

	RemoteStatic keys.PublicKey
}

func newPacketSession(sendKey, recvKey [keySize]byte, send func([]byte) error, rs keys.PublicKey) *PacketSession {
	sa, _ := chacha20poly1305.New(sendKey[:])
	ra, _ := chacha20poly1305.New(recvKey[:])
	return &PacketSession{sendAEAD: sa, recvAEAD: ra, send: send, RemoteStatic: rs}
}

// SetMaxPad sets the maximum random padding per datagram.
func (p *PacketSession) SetMaxPad(n int) { p.MaxPad = n }

// SetMaxPayload bounds the plaintext per datagram so the wrapped UDP packet
// stays within the path MTU (avoids fragmentation / drops).
func (p *PacketSession) SetMaxPayload(n int) { p.MaxPayload = n }

func (p *PacketSession) maxPad() int {
	if p.MaxPad <= 0 {
		return DefaultMaxPad
	}
	return p.MaxPad
}

func (p *PacketSession) sealAndSend(payload []byte) error {
	p.sendMu.Lock()
	ctr := p.sendCtr
	p.sendCtr++
	nonce := nonceFromCounter(ctr)
	out := make([]byte, 8, 8+len(payload)+tagSize)
	binary.BigEndian.PutUint64(out[:8], ctr)
	out = p.sendAEAD.Seal(out, nonce[:], payload, nil)
	err := p.send(out)
	p.sendMu.Unlock()
	return err
}

// WritePacket sends a single IP packet with random padding.
func (p *PacketSession) WritePacket(pkt []byte) error {
	pad := randPad(padLimit(p.maxPad(), p.MaxPayload, len(pkt)))
	payload := make([]byte, 0, len(pkt)+len(pad))
	payload = append(payload, pkt...)
	payload = append(payload, pad...)
	return p.sealAndSend(payload)
}

// WriteKeepalive sends an empty control datagram.
func (p *PacketSession) WriteKeepalive() error { return p.sealAndSend([]byte{0x00}) }

// WriteJunk sends a random-length cover-traffic datagram.
func (p *PacketSession) WriteJunk(maxSize int) error {
	n := randIntn(maxSize)
	payload := make([]byte, 1+n)
	if n > 0 {
		_, _ = rand.Read(payload[1:])
	}
	return p.sealAndSend(payload)
}

// RunCover sends cover traffic at randomised intervals (see Session.RunCover).
func (p *PacketSession) RunCover(maxInterval time.Duration, maxJunk int, stop <-chan struct{}) {
	if maxInterval <= 0 {
		maxInterval = 25 * time.Second
	}
	minInterval := maxInterval / 3
	spread := int(maxInterval - minInterval)
	for {
		d := minInterval + time.Duration(randIntn(spread))
		select {
		case <-stop:
			return
		case <-time.After(d):
		}
		if err := p.WriteJunk(maxJunk); err != nil {
			return
		}
	}
}

// open decrypts and anti-replay-checks one received datagram, returning the
// plaintext payload (inner packet plus padding). Authentication happens before
// the replay check so forged counters cannot advance the window.
func (p *PacketSession) open(datagram []byte) ([]byte, error) {
	if len(datagram) < 8+tagSize {
		return nil, errShort
	}
	ctr := binary.BigEndian.Uint64(datagram[:8])
	nonce := nonceFromCounter(ctr)
	pt, err := p.recvAEAD.Open(nil, nonce[:], datagram[8:], nil)
	if err != nil {
		return nil, errDecrypt
	}
	if !p.replay.validate(ctr) {
		return nil, errReplay
	}
	return pt, nil
}

// OpenPacket decrypts a datagram and returns the inner IP packet, or ok=false
// for control/junk datagrams (used by the server demux).
func (p *PacketSession) OpenPacket(datagram []byte) (pkt []byte, ok bool, err error) {
	pt, err := p.open(datagram)
	if err != nil {
		return nil, false, err
	}
	pkt, ok = extractIPPacket(pt)
	return pkt, ok, nil
}

// packetIdleTimeout tears down a client datagram session that has received
// nothing for this long, so the client reconnects (UDP has no connection close,
// and the server's cover traffic keeps a healthy link well within this window).
const packetIdleTimeout = 90 * time.Second

// PacketConn is the client-side datagram session over a connected UDP socket.
type PacketConn struct {
	*PacketSession
	conn net.Conn
}

func newPacketConn(conn net.Conn, sendKey, recvKey [keySize]byte, rs keys.PublicKey) *PacketConn {
	ps := newPacketSession(sendKey, recvKey, func(b []byte) error { _, e := conn.Write(b); return e }, rs)
	return &PacketConn{PacketSession: ps, conn: conn}
}

// ReadPacket returns the next inner IP packet, dropping bad/replayed datagrams
// and skipping control/junk.
func (c *PacketConn) ReadPacket() ([]byte, error) {
	buf := make([]byte, 65535)
	for {
		// Liveness: if nothing arrives within the idle window, fail so the client
		// reconnects (UDP gives no connection-closed signal).
		_ = c.conn.SetReadDeadline(time.Now().Add(packetIdleTimeout))
		n, err := c.conn.Read(buf)
		if err != nil {
			return nil, err
		}
		pkt, ok, oerr := c.OpenPacket(buf[:n])
		if oerr != nil {
			continue // drop spoofed/corrupt/replayed
		}
		if ok {
			return pkt, nil
		}
	}
}

// Close closes the underlying socket.
func (c *PacketConn) Close() error { return c.conn.Close() }

// --- datagram handshake ---

type packetExchanger struct {
	first []byte // a pre-received message (server side: message 1)
	read  func() ([]byte, error)
	write func([]byte) error
}

func (e *packetExchanger) sendMsg(m []byte) error { return e.write(m) }

func (e *packetExchanger) recvMsg() ([]byte, error) {
	if e.first != nil {
		m := e.first
		e.first = nil
		return m, nil
	}
	return e.read()
}

// InitiatePacket runs the client handshake over a connected UDP conn and returns
// a datagram PacketConn plus the server's response payload.
func InitiatePacket(conn net.Conn, localStatic keys.PrivateKey, remoteStatic keys.PublicKey, psk [32]byte, payload []byte) (*PacketConn, []byte, error) {
	exch := &packetExchanger{
		read: func() ([]byte, error) {
			b := make([]byte, 2048)
			n, err := conn.Read(b)
			if err != nil {
				return nil, err
			}
			return b[:n], nil
		},
		write: func(m []byte) error { _, err := conn.Write(m); return err },
	}
	send, recv, resp, err := initiate(exch, localStatic, remoteStatic, psk, payload)
	if err != nil {
		return nil, nil, err
	}
	return newPacketConn(conn, send.key, recv.key, remoteStatic), resp, nil
}

// RespondPacket runs the server handshake for a client whose first datagram
// (message 1) has already been received, using write to send message 2 and all
// subsequent datagrams to that client. It returns a server-side PacketSession.
func RespondPacket(firstMsg []byte, localStatic keys.PrivateKey, auth Authorizer, write func([]byte) error) (*PacketSession, keys.PublicKey, []byte, error) {
	exch := &packetExchanger{first: firstMsg, write: write}
	send, recv, rs, payload1, err := respond(exch, localStatic, auth)
	if err != nil {
		return nil, rs, payload1, err
	}
	return newPacketSession(send.key, recv.key, write, rs), rs, payload1, nil
}
