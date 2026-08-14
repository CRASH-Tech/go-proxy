package noise

import (
	"bytes"
	"net"
	"testing"
	"time"

	"goproxy/internal/keys"
)

func TestPacketHandshakeAndData(t *testing.T) {
	clientPriv, _ := keys.GeneratePrivateKey()
	serverPriv, _ := keys.GeneratePrivateKey()
	psk := [32]byte{7, 7, 7}

	c1, c2 := net.Pipe() // one Write == one datagram
	response := []byte(`{"client_ip":"10.9.0.2"}`)
	hello := []byte(`{"ts":1}`)

	type sres struct {
		ps      *PacketSession
		payload []byte
		err     error
	}
	srvCh := make(chan sres, 1)
	go func() {
		// Read the first datagram (message 1), then respond.
		b := make([]byte, 2048)
		n, err := c2.Read(b)
		if err != nil {
			srvCh <- sres{err: err}
			return
		}
		auth := func(pub keys.PublicKey) ([32]byte, []byte, bool) {
			if pub != clientPriv.Public() {
				return [32]byte{}, nil, false
			}
			return psk, response, true
		}
		ps, _, payload1, err := RespondPacket(b[:n], serverPriv, auth, func(m []byte) error {
			_, e := c2.Write(m)
			return e
		})
		srvCh <- sres{ps, payload1, err}
	}()

	pc, resp, err := InitiatePacket(c1, clientPriv, serverPriv.Public(), psk, hello)
	if err != nil {
		t.Fatalf("InitiatePacket: %v", err)
	}
	srv := <-srvCh
	if srv.err != nil {
		t.Fatalf("RespondPacket: %v", srv.err)
	}
	if !bytes.Equal(resp, response) {
		t.Fatalf("client response %q != %q", resp, response)
	}
	if !bytes.Equal(srv.payload, hello) {
		t.Fatalf("server payload %q != %q", srv.payload, hello)
	}

	// Data: client -> server.
	pkt := ipv4Packet([4]byte{10, 9, 0, 2}, [4]byte{1, 1, 1, 1}, []byte("datagram hi"))
	go func() { _ = pc.WritePacket(pkt) }()
	b := make([]byte, 65535)
	n, err := c2.Read(b)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := srv.ps.OpenPacket(b[:n])
	if err != nil || !ok {
		t.Fatalf("server OpenPacket: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got, pkt) {
		t.Fatalf("server got %x want %x", got, pkt)
	}

	// Replay of the same datagram must be rejected.
	if _, _, err := srv.ps.OpenPacket(b[:n]); err != errReplay {
		t.Fatalf("expected replay rejection, got %v", err)
	}

	// Data: server -> client, and a junk datagram is skipped.
	pkt2 := ipv4Packet([4]byte{1, 1, 1, 1}, [4]byte{10, 9, 0, 2}, []byte("reply"))
	go func() {
		_ = srv.ps.WriteJunk(64)
		_ = srv.ps.WritePacket(pkt2)
	}()
	pc.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got2, err := pc.ReadPacket()
	if err != nil {
		t.Fatalf("client ReadPacket: %v", err)
	}
	if !bytes.Equal(got2, pkt2) {
		t.Fatalf("client got %x want %x", got2, pkt2)
	}
}
