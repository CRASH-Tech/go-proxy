package noise

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"goproxy/internal/keys"
)

// ipv4Packet builds a minimal well-formed IPv4 packet with the given payload.
func ipv4Packet(src, dst [4]byte, payload []byte) []byte {
	total := 20 + len(payload)
	p := make([]byte, total)
	p[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	p[8] = 64  // TTL
	p[9] = 1   // protocol ICMP (arbitrary)
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	copy(p[20:], payload)
	return p
}

type hsResult struct {
	sess    *Session
	payload []byte
	err     error
}

func runHandshake(t *testing.T, clientPriv keys.PrivateKey, serverPriv keys.PrivateKey,
	clientPSK, serverPSK [32]byte, auth Authorizer, hello []byte) (cli, srv hsResult) {
	t.Helper()
	c1, c2 := net.Pipe()

	cliCh := make(chan hsResult, 1)
	srvCh := make(chan hsResult, 1)

	go func() {
		sess, payload, err := Initiate(c1, clientPriv, serverPriv.Public(), clientPSK, hello)
		if err != nil {
			c1.Close() // mirror real handleConn: close on failure so the peer unblocks
		}
		cliCh <- hsResult{sess, payload, err}
	}()
	go func() {
		sess, _, payload, err := Respond(c2, serverPriv, auth)
		if err != nil {
			c2.Close()
		}
		srvCh <- hsResult{sess, payload, err}
	}()

	select {
	case cli = <-cliCh:
	case <-time.After(3 * time.Second):
		t.Fatal("client handshake timed out")
	}
	select {
	case srv = <-srvCh:
	case <-time.After(3 * time.Second):
		t.Fatal("server handshake timed out")
	}
	return cli, srv
}

func TestHandshakeAndRoundTrip(t *testing.T) {
	clientPriv, _ := keys.GeneratePrivateKey()
	serverPriv, _ := keys.GeneratePrivateKey()
	psk := [32]byte{1, 2, 3, 4}

	response := []byte(`{"client_ip":"10.8.0.2"}`)
	auth := func(pub keys.PublicKey) ([32]byte, []byte, bool) {
		if pub != clientPriv.Public() {
			return [32]byte{}, nil, false
		}
		return psk, response, true
	}

	hello := []byte(`{"ts":123}`)
	cli, srv := runHandshake(t, clientPriv, serverPriv, psk, psk, auth, hello)
	if cli.err != nil {
		t.Fatalf("client handshake: %v", cli.err)
	}
	if srv.err != nil {
		t.Fatalf("server handshake: %v", srv.err)
	}
	if !bytes.Equal(cli.payload, response) {
		t.Fatalf("client got response %q, want %q", cli.payload, response)
	}
	if !bytes.Equal(srv.payload, hello) {
		t.Fatalf("server got hello %q, want %q", srv.payload, hello)
	}
	if srv.sess.RemoteStatic != clientPriv.Public() {
		t.Fatalf("server learned wrong client static key")
	}

	// Data path: client -> server.
	pkt := ipv4Packet([4]byte{10, 8, 0, 2}, [4]byte{1, 1, 1, 1}, []byte("hello world"))
	go func() { _ = cli.sess.WritePacket(pkt) }()
	got, err := srv.sess.ReadPacket()
	if err != nil {
		t.Fatalf("server ReadPacket: %v", err)
	}
	if !bytes.Equal(got, pkt) {
		t.Fatalf("server got %x, want %x", got, pkt)
	}

	// Data path: server -> client, and keepalive should be skipped transparently.
	pkt2 := ipv4Packet([4]byte{1, 1, 1, 1}, [4]byte{10, 8, 0, 2}, []byte("reply!"))
	go func() {
		_ = srv.sess.WriteKeepalive()
		_ = srv.sess.WritePacket(pkt2)
	}()
	got2, err := cli.sess.ReadPacket()
	if err != nil {
		t.Fatalf("client ReadPacket: %v", err)
	}
	if !bytes.Equal(got2, pkt2) {
		t.Fatalf("client got %x, want %x", got2, pkt2)
	}
}

func TestHandshakeWrongPSK(t *testing.T) {
	clientPriv, _ := keys.GeneratePrivateKey()
	serverPriv, _ := keys.GeneratePrivateKey()
	auth := func(pub keys.PublicKey) ([32]byte, []byte, bool) {
		return [32]byte{9, 9, 9}, nil, true // server uses a different psk
	}
	cli, _ := runHandshake(t, clientPriv, serverPriv, [32]byte{1}, [32]byte{}, auth, []byte("{}"))
	if cli.err == nil {
		t.Fatal("expected client handshake to fail with mismatched PSK")
	}
}

func TestHandshakeUnauthorized(t *testing.T) {
	clientPriv, _ := keys.GeneratePrivateKey()
	serverPriv, _ := keys.GeneratePrivateKey()
	auth := func(pub keys.PublicKey) ([32]byte, []byte, bool) {
		return [32]byte{}, nil, false // reject everyone
	}
	_, srv := runHandshake(t, clientPriv, serverPriv, [32]byte{}, [32]byte{}, auth, []byte("{}"))
	if srv.err == nil {
		t.Fatal("expected server handshake to fail for unauthorized client")
	}
}
