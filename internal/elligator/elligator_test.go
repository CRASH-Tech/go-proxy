package elligator

import (
	"crypto/rand"
	"testing"

	"goproxy/internal/keys"
)

// TestRoundTrip checks that Decode(Encode(pub)) == pub for many keys, and that
// the two high bits are actually randomised without breaking the round-trip.
func TestRoundTrip(t *testing.T) {
	representable := 0
	const iters = 2000
	for i := 0; i < iters; i++ {
		priv, err := keys.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		pub := priv.Public()
		repr, ok := Encode([32]byte(pub))
		if !ok {
			continue
		}
		representable++
		got := Decode(repr)
		if got != [32]byte(pub) {
			t.Fatalf("round-trip mismatch:\n pub=%x\n got=%x\nrepr=%x", pub, got, repr)
		}
	}
	// Roughly half of keys should be representable; make sure it's not degenerate.
	if representable < iters/4 {
		t.Fatalf("only %d/%d keys representable, expected ~half", representable, iters)
	}
	t.Logf("representable: %d/%d", representable, iters)
}

// TestHighBitsRandomised checks that the top two bits of the representative vary
// (they carry random noise), so the encoding is not trivially distinguishable.
func TestHighBitsRandomised(t *testing.T) {
	seen := map[byte]bool{}
	for i := 0; i < 500; i++ {
		priv, _ := keys.GeneratePrivateKey()
		repr, ok := Encode([32]byte(priv.Public()))
		if !ok {
			continue
		}
		seen[repr[31]&0xc0] = true
	}
	if len(seen) < 3 {
		t.Fatalf("top two bits not well randomised: saw %d distinct patterns", len(seen))
	}
}

// TestDecodeIsTotal checks that any uniform 32-byte string decodes to a valid,
// non-zero X25519 public key (so a passive observer's random bytes always look
// like a real ephemeral, and the peer can always complete DH).
func TestDecodeIsTotal(t *testing.T) {
	var zero [32]byte
	for i := 0; i < 500; i++ {
		var b [32]byte
		_, _ = rand.Read(b[:])
		pub := Decode(b)
		if pub == zero {
			t.Fatalf("decoded to zero public key from %x", b)
		}
		// A decoded key must be usable for X25519.
		var kpub keys.PublicKey = pub
		priv, _ := keys.GeneratePrivateKey()
		if _, err := keys.DH(priv, kpub); err != nil {
			t.Fatalf("decoded key not usable for DH: %v", err)
		}
	}
}

// TestDHAgreement verifies a full Elligator-wrapped ephemeral DH: the value sent
// on the wire is the representative, but both sides agree on the shared secret.
func TestDHAgreement(t *testing.T) {
	// Bob has a static key.
	bobPriv, _ := keys.GeneratePrivateKey()
	bobPub := bobPriv.Public()

	// Alice makes a representable ephemeral.
	var aliceRepr [32]byte
	var alicePriv keys.PrivateKey
	for {
		alicePriv, _ = keys.GeneratePrivateKey()
		var ok bool
		aliceRepr, ok = Encode([32]byte(alicePriv.Public()))
		if ok {
			break
		}
	}

	// Bob decodes the representative and does DH with his static private key.
	aliceEph := keys.PublicKey(Decode(aliceRepr))
	bobShared, err := keys.DH(bobPriv, aliceEph)
	if err != nil {
		t.Fatal(err)
	}
	aliceShared, err := keys.DH(alicePriv, bobPub)
	if err != nil {
		t.Fatal(err)
	}
	if string(bobShared) != string(aliceShared) {
		t.Fatalf("DH mismatch:\n alice=%x\n bob=%x", aliceShared, bobShared)
	}
}
