package noise

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"goproxy/internal/keys"
)

// CoverMaxJunk is the maximum size of a random cover-traffic record.
const CoverMaxJunk = 1024

// maxRecord bounds the plaintext length of a single record (inner IP packet
// plus padding). Two-byte length prefix limits this to 65535.
const maxRecord = 65535

// DefaultMaxPad is the default maximum random padding appended to each record
// to defeat packet-size fingerprinting.
const DefaultMaxPad = 255

// Session is an established, encrypted record channel over a net.Conn. Records
// carry raw IP packets. Lengths are themselves encrypted so an observer sees
// only an opaque byte stream.
type Session struct {
	conn net.Conn

	sendMu sync.Mutex
	send   *cipherState
	recv   *cipherState

	MaxPad int

	// RemoteStatic is the peer's static public key (identity).
	RemoteStatic keys.PublicKey
}

// Conn exposes the underlying connection (for deadlines, remote addr, etc.).
func (s *Session) Conn() net.Conn { return s.conn }

// Close closes the underlying connection.
func (s *Session) Close() error { return s.conn.Close() }

func (s *Session) maxPad() int {
	if s.MaxPad <= 0 {
		return DefaultMaxPad
	}
	return s.MaxPad
}

// writeRecord encrypts and writes one plaintext payload as two AEAD records
// (encrypted length, then encrypted body).
func (s *Session) writeRecord(payload []byte) error {
	if len(payload) > maxRecord {
		return fmt.Errorf("noise: record too large (%d)", len(payload))
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	encLen, err := s.send.encrypt(nil, lenBuf[:])
	if err != nil {
		return err
	}
	encBody, err := s.send.encrypt(nil, payload)
	if err != nil {
		return err
	}
	// Single Write so the two records are not split across TCP writes
	// unnecessarily (helps keep record boundaries opaque).
	out := make([]byte, 0, len(encLen)+len(encBody))
	out = append(out, encLen...)
	out = append(out, encBody...)
	_, err = s.conn.Write(out)
	return err
}

// WritePacket sends a single IP packet through the tunnel, with random padding.
func (s *Session) WritePacket(pkt []byte) error {
	pad := randPad(s.maxPad())
	// Ensure we do not exceed the record limit after padding.
	if len(pkt)+len(pad) > maxRecord {
		pad = pad[:maxRecord-len(pkt)]
	}
	payload := make([]byte, 0, len(pkt)+len(pad))
	payload = append(payload, pkt...)
	payload = append(payload, pad...)
	return s.writeRecord(payload)
}

// WriteKeepalive sends an empty control record to keep NAT/connection state alive.
func (s *Session) WriteKeepalive() error {
	// A single zero byte: version nibble 0, recognised as a non-IP control record.
	return s.writeRecord([]byte{0x00})
}

// randIntn returns a uniform random int in [0, max].
func randIntn(max int) int {
	if max <= 0 {
		return 0
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:]) % uint32(max+1))
}

// WriteJunk sends a random-length cover-traffic record. The payload starts with
// a 0x00 marker (version nibble 0) so the peer discards it, and its size is
// randomised to add to the on-wire length distribution. It also serves as a
// keepalive.
func (s *Session) WriteJunk(maxSize int) error {
	n := randIntn(maxSize)
	payload := make([]byte, 1+n)
	// payload[0] == 0x00 -> not IPv4/IPv6 -> receiver skips it (see ReadPacket).
	if n > 0 {
		_, _ = rand.Read(payload[1:])
	}
	return s.writeRecord(payload)
}

// RunCover sends cover-traffic records at randomised intervals until stop is
// closed or the session fails. Each interval is chosen in [maxInterval/3,
// maxInterval], so it also keeps NAT/connection state alive without the regular
// heartbeat that a fixed keepalive would produce.
func (s *Session) RunCover(maxInterval time.Duration, maxJunk int, stop <-chan struct{}) {
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
		if err := s.WriteJunk(maxJunk); err != nil {
			return
		}
	}
}

// readRecord reads and decrypts one length-prefixed record, returning the
// plaintext payload (inner packet plus padding).
func (s *Session) readRecord() ([]byte, error) {
	encLen := make([]byte, 2+tagSize)
	if _, err := io.ReadFull(s.conn, encLen); err != nil {
		return nil, err
	}
	lenBuf, err := s.recv.decrypt(nil, encLen)
	if err != nil {
		return nil, errDecrypt
	}
	n := int(binary.BigEndian.Uint16(lenBuf))
	encBody := make([]byte, n+tagSize)
	if _, err := io.ReadFull(s.conn, encBody); err != nil {
		return nil, err
	}
	payload, err := s.recv.decrypt(nil, encBody)
	if err != nil {
		return nil, errDecrypt
	}
	return payload, nil
}

// ReadPacket returns the next inner IP packet, transparently skipping keepalive
// and padding. The returned slice is exactly the IP packet (padding stripped).
func (s *Session) ReadPacket() ([]byte, error) {
	for {
		payload, err := s.readRecord()
		if err != nil {
			return nil, err
		}
		pkt, ok := extractIPPacket(payload)
		if !ok {
			// Keepalive or unrecognised control record; keep reading.
			continue
		}
		return pkt, nil
	}
}

// extractIPPacket parses the leading IP header to find the true packet length,
// stripping any trailing padding. Returns false for non-IP (control) records.
func extractIPPacket(payload []byte) ([]byte, bool) {
	if len(payload) < 1 {
		return nil, false
	}
	version := payload[0] >> 4
	switch version {
	case 4:
		if len(payload) < 20 {
			return nil, false
		}
		total := int(binary.BigEndian.Uint16(payload[2:4]))
		if total < 20 || total > len(payload) {
			return nil, false
		}
		return payload[:total], true
	case 6:
		if len(payload) < 40 {
			return nil, false
		}
		total := 40 + int(binary.BigEndian.Uint16(payload[4:6]))
		if total > len(payload) {
			return nil, false
		}
		return payload[:total], true
	default:
		return nil, false
	}
}
