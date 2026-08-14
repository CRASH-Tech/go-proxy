// Package noise implements a small subset of the Noise Protocol Framework,
// specifically the Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s handshake used to
// authenticate peers and derive forward-secret transport keys. On top of the
// handshake it provides a length-hiding, padded AEAD record layer used to
// carry raw IP packets between the tunnel endpoints.
//
// The handshake is the same construction WireGuard is built on. Implementing
// it directly (rather than pulling a dependency) keeps the wire format fully
// under our control, which matters for the anti-DPI goals: in "aead" transport
// mode the very first bytes on the wire are an ephemeral public key followed
// by ciphertext, i.e. indistinguishable from random.
package noise

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keySize   = 32
	hashSize  = 32
	nonceSize = chacha20poly1305.NonceSize // 12
	tagSize   = 16
)

func newHash() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic("noise: blake2s init failed: " + err.Error())
	}
	return h
}

func hashData(data ...[]byte) [hashSize]byte {
	h := newHash()
	for _, d := range data {
		h.Write(d)
	}
	var out [hashSize]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hmacHash computes HMAC-BLAKE2s(key, data...).
func hmacHash(key []byte, data ...[]byte) [hashSize]byte {
	mac := hmac.New(newHash, key)
	for _, d := range data {
		mac.Write(d)
	}
	var out [hashSize]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// hkdf implements the Noise HKDF, returning n (1..3) 32-byte outputs.
func hkdf(chainingKey, input []byte, n int) [][hashSize]byte {
	tempKey := hmacHash(chainingKey, input)
	out := make([][hashSize]byte, 0, n)

	out1 := hmacHash(tempKey[:], []byte{0x01})
	out = append(out, out1)
	if n == 1 {
		return out
	}
	out2 := hmacHash(tempKey[:], out1[:], []byte{0x02})
	out = append(out, out2)
	if n == 2 {
		return out
	}
	out3 := hmacHash(tempKey[:], out2[:], []byte{0x03})
	out = append(out, out3)
	return out
}

// cipherState is a Noise CipherState: an AEAD key plus a monotonic nonce.
type cipherState struct {
	key    [keySize]byte
	nonce  uint64
	hasKey bool
}

func (c *cipherState) initializeKey(key [keySize]byte) {
	c.key = key
	c.nonce = 0
	c.hasKey = true
}

func (c *cipherState) nonceBytes() [nonceSize]byte {
	var n [nonceSize]byte
	// 32 bits of zero prefix, then 64-bit little-endian counter (WireGuard/Noise).
	binary.LittleEndian.PutUint64(n[4:], c.nonce)
	return n
}

func (c *cipherState) encrypt(ad, plaintext []byte) ([]byte, error) {
	if !c.hasKey {
		return append([]byte(nil), plaintext...), nil
	}
	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return nil, err
	}
	n := c.nonceBytes()
	ct := aead.Seal(nil, n[:], plaintext, ad)
	c.nonce++
	return ct, nil
}

func (c *cipherState) decrypt(ad, ciphertext []byte) ([]byte, error) {
	if !c.hasKey {
		return append([]byte(nil), ciphertext...), nil
	}
	aead, err := chacha20poly1305.New(c.key[:])
	if err != nil {
		return nil, err
	}
	n := c.nonceBytes()
	pt, err := aead.Open(nil, n[:], ciphertext, ad)
	if err != nil {
		return nil, err
	}
	c.nonce++
	return pt, nil
}

// symmetricState is the Noise SymmetricState.
type symmetricState struct {
	chainingKey [hashSize]byte
	hash        [hashSize]byte
	cs          cipherState
}

func newSymmetricState(protocolName string) *symmetricState {
	s := &symmetricState{}
	name := []byte(protocolName)
	if len(name) <= hashSize {
		var h [hashSize]byte
		copy(h[:], name)
		s.hash = h
	} else {
		s.hash = hashData(name)
	}
	s.chainingKey = s.hash
	return s
}

func (s *symmetricState) mixKey(input []byte) {
	out := hkdf(s.chainingKey[:], input, 2)
	s.chainingKey = out[0]
	s.cs.initializeKey(out[1])
}

func (s *symmetricState) mixHash(data []byte) {
	s.hash = hashData(s.hash[:], data)
}

// mixKeyAndHash is used for the PSK token.
func (s *symmetricState) mixKeyAndHash(input []byte) {
	out := hkdf(s.chainingKey[:], input, 3)
	s.chainingKey = out[0]
	s.mixHash(out[1][:])
	s.cs.initializeKey(out[2])
}

func (s *symmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	ct, err := s.cs.encrypt(s.hash[:], plaintext)
	if err != nil {
		return nil, err
	}
	s.mixHash(ct)
	return ct, nil
}

func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	pt, err := s.cs.decrypt(s.hash[:], ciphertext)
	if err != nil {
		return nil, err
	}
	s.mixHash(ciphertext)
	return pt, nil
}

// split derives the two transport CipherStates (initiator->responder,
// responder->initiator).
func (s *symmetricState) split() (*cipherState, *cipherState) {
	out := hkdf(s.chainingKey[:], nil, 2)
	c1 := &cipherState{}
	c2 := &cipherState{}
	c1.initializeKey(out[0])
	c2.initializeKey(out[1])
	return c1, c2
}

var errDecrypt = errors.New("noise: decryption failed")
