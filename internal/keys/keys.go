// Package keys handles X25519 static key material used for peer identity
// and authorization (WireGuard-style: a peer is authorized if the server
// knows its public key).
package keys

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the size of an X25519 key in bytes.
const KeySize = 32

// PrivateKey is a 32-byte X25519 private (scalar) key.
type PrivateKey [KeySize]byte

// PublicKey is a 32-byte X25519 public key.
type PublicKey [KeySize]byte

// GeneratePrivateKey returns a fresh random X25519 private key with the
// standard clamping applied.
func GeneratePrivateKey() (PrivateKey, error) {
	var k PrivateKey
	if _, err := rand.Read(k[:]); err != nil {
		return k, err
	}
	// Clamp as required by X25519.
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k, nil
}

// Public derives the public key corresponding to a private key.
func (p PrivateKey) Public() PublicKey {
	var pub PublicKey
	// curve25519.ScalarBaseMult is deprecated in favour of X25519 with the
	// basepoint, but it is the clearest way to derive the public key.
	out, err := curve25519.X25519(p[:], curve25519.Basepoint)
	if err != nil {
		// Only fails on all-zero scalar, which clamping prevents.
		panic("keys: X25519 basepoint failed: " + err.Error())
	}
	copy(pub[:], out)
	return pub
}

// DH performs the X25519 Diffie-Hellman operation between a private key and a
// peer public key. It returns an error if the result is a low-order point.
func DH(priv PrivateKey, pub PublicKey) ([]byte, error) {
	shared, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return nil, fmt.Errorf("dh: %w", err)
	}
	return shared, nil
}

// String returns the base64 (standard, padded) encoding of the private key.
func (p PrivateKey) String() string { return base64.StdEncoding.EncodeToString(p[:]) }

// String returns the base64 (standard, padded) encoding of the public key.
func (p PublicKey) String() string { return base64.StdEncoding.EncodeToString(p[:]) }

// ParsePrivateKey decodes a base64-encoded private key.
func ParsePrivateKey(s string) (PrivateKey, error) {
	var k PrivateKey
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("parse private key: %w", err)
	}
	if len(b) != KeySize {
		return k, fmt.Errorf("parse private key: expected %d bytes, got %d", KeySize, len(b))
	}
	copy(k[:], b)
	return k, nil
}

// ParsePublicKey decodes a base64-encoded public key.
func ParsePublicKey(s string) (PublicKey, error) {
	var k PublicKey
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("parse public key: %w", err)
	}
	if len(b) != KeySize {
		return k, fmt.Errorf("parse public key: expected %d bytes, got %d", KeySize, len(b))
	}
	copy(k[:], b)
	return k, nil
}
