// Package elligator implements the Elligator2 map for Curve25519, used to encode
// an X25519 public key as a 32-byte string that is indistinguishable from
// uniform random. This removes the statistical signature an X25519 ephemeral key
// otherwise leaves on the wire (obfs4 uses the same technique).
//
// The map and its inverse follow the reference by Bernstein, Hamburg, Krasnova
// and Lange, as implemented in Loup Vaillant's public-domain Monocypher. Field
// arithmetic is provided by filippo.io/edwards25519/field.
//
// Decoding masks the two most-significant bits of the input, and because a
// representative r is always <= (p-1)/2 < 2^254, encoding fills those two bits
// with random noise — so the round-trip is exact while the wire bytes look fully
// random.
package elligator

import (
	"crypto/rand"

	"filippo.io/edwards25519/field"
)

var (
	feA    *field.Element // Montgomery curve constant A = 486662
	feNegA *field.Element
	feOne  = new(field.Element).One()
)

func init() {
	var b [32]byte
	b[0], b[1], b[2] = 0x06, 0x6d, 0x07 // 486662, little-endian
	feA, _ = new(field.Element).SetBytes(b[:])
	feNegA = new(field.Element).Negate(feA)
}

func isSquare(x *field.Element) bool {
	_, wasSquare := new(field.Element).SqrtRatio(x, feOne)
	return wasSquare == 1
}

// canRepresent reports whether the point with u-coordinate u has an Elligator2
// representative: u != -A and -2*u*(u+A) is a square.
func canRepresent(u *field.Element) bool {
	if u.Equal(feNegA) == 1 {
		return false
	}
	uA := new(field.Element).Add(u, feA)
	t := new(field.Element).Multiply(u, uA)
	t.Mult32(t, 2)
	t.Negate(t)
	return isSquare(t)
}

// Encode maps an X25519 public key to a uniform-looking 32-byte representative.
// It returns ok=false for the ~50% of keys that are not representable; the
// caller should generate a different ephemeral key and retry.
func Encode(pub [32]byte) (repr [32]byte, ok bool) {
	u, err := new(field.Element).SetBytes(pub[:])
	if err != nil {
		return repr, false
	}
	if !canRepresent(u) {
		return repr, false
	}

	uA := new(field.Element).Add(u, feA)
	// Randomly choose which of the two representatives (v-sign branches) to use.
	var vbit [1]byte
	_, _ = rand.Read(vbit[:])

	var num, den *field.Element
	if vbit[0]&1 == 1 {
		num = new(field.Element).Negate(uA)     // -(u+A)
		den = new(field.Element).Mult32(u, 2)    // 2u
	} else {
		num = new(field.Element).Negate(u)       // -u
		den = new(field.Element).Mult32(uA, 2)   // 2(u+A)
	}
	r, wasSquare := new(field.Element).SqrtRatio(num, den)
	if wasSquare != 1 {
		return repr, false
	}
	// SqrtRatio's "non-negative" root uses the even-LSB convention, so r may be
	// >= 2^254. We need r < 2^254 (bit 254 clear) so the two high bits are free
	// for randomisation. r and p-r have the same square, so negate if needed.
	rb := r.Bytes()
	if rb[31]&0x40 != 0 {
		r.Negate(r)
		rb = r.Bytes()
	}
	copy(repr[:], rb)
	// Fill the two now-unused high bits with random noise.
	var tw [1]byte
	_, _ = rand.Read(tw[:])
	repr[31] |= tw[0] & 0xc0
	return repr, true
}

// Decode maps a 32-byte representative back to an X25519 public key. It is total:
// any 32-byte input decodes to a valid public key.
func Decode(repr [32]byte) (pub [32]byte) {
	repr[31] &= 0x3f // discard the two random high bits
	r, _ := new(field.Element).SetBytes(repr[:])

	// w = -A / (1 + 2*r^2)
	r2 := new(field.Element).Square(r)
	r2.Mult32(r2, 2)
	r2.Add(r2, feOne)
	w := new(field.Element).Invert(r2)
	w.Multiply(w, feA)
	w.Negate(w)

	// e = chi(w^3 + A*w^2 + w) = chi(w*(w^2 + A*w + 1))
	t := new(field.Element).Square(w)
	aw := new(field.Element).Multiply(feA, w)
	t.Add(t, aw)
	t.Add(t, feOne)
	t.Multiply(t, w)

	// u = w if that expression is a square, else -w - A.
	uAlt := new(field.Element).Negate(w)
	uAlt.Subtract(uAlt, feA)
	u := new(field.Element).Select(w, uAlt, boolToInt(isSquare(t)))

	copy(pub[:], u.Bytes())
	return pub
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
