package noise

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"goproxy/internal/elligator"
	"goproxy/internal/keys"
)

const protocolName = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

// maxHandshakeMsg bounds the size of a handshake message we are willing to read.
const maxHandshakeMsg = 4096

// Authorizer is called by the responder once it has learned (and cryptographically
// verified control of) the initiator's static public key. It returns the pre-shared
// key to mix in, a response payload to send back, and whether the peer is authorized.
type Authorizer func(remoteStatic keys.PublicKey) (psk [32]byte, response []byte, ok bool)

func writeFrame(w io.Writer, msg []byte) error {
	if len(msg) > maxHandshakeMsg {
		return fmt.Errorf("noise: handshake message too large (%d)", len(msg))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if int(n) > maxHandshakeMsg {
		return nil, fmt.Errorf("noise: handshake message too large (%d)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func newEphemeral() (keys.PrivateKey, keys.PublicKey, error) {
	priv, err := keys.GeneratePrivateKey()
	if err != nil {
		return priv, keys.PublicKey{}, err
	}
	return priv, priv.Public(), nil
}

// newRepresentableEphemeral generates an ephemeral keypair whose public key has
// an Elligator2 representative (about half do), returning the private key, the
// public key, and the representative to send on the wire.
func newRepresentableEphemeral() (keys.PrivateKey, keys.PublicKey, [32]byte, error) {
	for i := 0; i < 128; i++ {
		priv, pub, err := newEphemeral()
		if err != nil {
			return priv, pub, [32]byte{}, err
		}
		if repr, ok := elligator.Encode([32]byte(pub)); ok {
			return priv, pub, repr, nil
		}
	}
	return keys.PrivateKey{}, keys.PublicKey{}, [32]byte{}, fmt.Errorf("noise: no representable ephemeral")
}

// Initiate runs the client side of the handshake over a stream conn and returns
// the established stream Session plus the response payload sent by the server.
func Initiate(conn net.Conn, localStatic keys.PrivateKey, remoteStatic keys.PublicKey, psk [32]byte, payload []byte) (*Session, []byte, error) {
	send, recv, resp, err := initiate(streamExchanger{conn}, localStatic, remoteStatic, psk, payload)
	if err != nil {
		return nil, nil, err
	}
	return &Session{conn: conn, send: send, recv: recv, RemoteStatic: remoteStatic}, resp, nil
}

// initiate performs the initiator handshake over an abstract message exchange,
// returning the two transport cipherstates (initiator->responder,
// responder->initiator) and the server's response payload.
func initiate(exch msgExchanger, localStatic keys.PrivateKey, remoteStatic keys.PublicKey, psk [32]byte, payload []byte) (*cipherState, *cipherState, []byte, error) {
	ss := newSymmetricState(protocolName)
	ss.mixHash(remoteStatic[:]) // pre-message: responder static

	ePriv, ePub, erep, err := newRepresentableEphemeral()
	if err != nil {
		return nil, nil, nil, err
	}

	// -> e (sent as an Elligator2 representative: looks like uniform random)
	ss.mixHash(ePub[:])
	msg := append([]byte(nil), erep[:]...)

	// es = DH(e, rs)
	es, err := keys.DH(ePriv, remoteStatic)
	if err != nil {
		return nil, nil, nil, err
	}
	ss.mixKey(es)

	// s (encrypted static)
	localPub := localStatic.Public()
	encS, err := ss.encryptAndHash(localPub[:])
	if err != nil {
		return nil, nil, nil, err
	}
	msg = append(msg, encS...)

	// ss = DH(s, rs)
	sss, err := keys.DH(localStatic, remoteStatic)
	if err != nil {
		return nil, nil, nil, err
	}
	ss.mixKey(sss)

	// payload
	encP, err := ss.encryptAndHash(payload)
	if err != nil {
		return nil, nil, nil, err
	}
	msg = append(msg, encP...)

	if err := exch.sendMsg(msg); err != nil {
		return nil, nil, nil, err
	}

	// <- message 2: e, ee, se, psk, payload
	buf, err := exch.recvMsg()
	if err != nil {
		return nil, nil, nil, err
	}
	if len(buf) < keySize {
		return nil, nil, nil, fmt.Errorf("noise: short message 2")
	}
	var frep [32]byte
	copy(frep[:], buf[:keySize])
	rfPub := keys.PublicKey(elligator.Decode(frep))
	ss.mixHash(rfPub[:])

	ee, err := keys.DH(ePriv, rfPub)
	if err != nil {
		return nil, nil, nil, err
	}
	ss.mixKey(ee)

	se, err := keys.DH(localStatic, rfPub)
	if err != nil {
		return nil, nil, nil, err
	}
	ss.mixKey(se)

	ss.mixKeyAndHash(psk[:])

	respPayload, err := ss.decryptAndHash(buf[keySize:])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("noise: %w (server rejected or wrong keys/psk)", errDecrypt)
	}

	c1, c2 := ss.split()
	return c1, c2, respPayload, nil // c1: i->r (send), c2: r->i (recv)
}

// Respond runs the server side of the handshake over conn. It returns the
// established Session, the initiator's verified static public key, and the
// payload the initiator sent in message 1.
func Respond(conn net.Conn, localStatic keys.PrivateKey, auth Authorizer) (*Session, keys.PublicKey, []byte, error) {
	send, recv, remoteStatic, payload1, err := respond(streamExchanger{conn}, localStatic, auth)
	if err != nil {
		return nil, remoteStatic, payload1, err
	}
	return &Session{conn: conn, send: send, recv: recv, RemoteStatic: remoteStatic}, remoteStatic, payload1, nil
}

// respond performs the responder handshake over an abstract message exchange,
// returning the two transport cipherstates (responder->initiator=send,
// initiator->responder=recv), the peer's static key and its message-1 payload.
func respond(exch msgExchanger, localStatic keys.PrivateKey, auth Authorizer) (*cipherState, *cipherState, keys.PublicKey, []byte, error) {
	var remoteStatic keys.PublicKey

	ss := newSymmetricState(protocolName)
	localPub := localStatic.Public()
	ss.mixHash(localPub[:]) // pre-message: our static

	buf, err := exch.recvMsg()
	if err != nil {
		return nil, nil, remoteStatic, nil, err
	}
	// message 1 = e(32) | encStatic(48) | encPayload(>=16)
	if len(buf) < keySize+keySize+tagSize+tagSize {
		return nil, nil, remoteStatic, nil, fmt.Errorf("noise: short message 1")
	}
	var erep [32]byte
	copy(erep[:], buf[:keySize])
	rePub := keys.PublicKey(elligator.Decode(erep))
	ss.mixHash(rePub[:])

	es, err := keys.DH(localStatic, rePub)
	if err != nil {
		return nil, nil, remoteStatic, nil, err
	}
	ss.mixKey(es)

	encStatic := buf[keySize : keySize+keySize+tagSize]
	rsBytes, err := ss.decryptAndHash(encStatic)
	if err != nil {
		return nil, nil, remoteStatic, nil, fmt.Errorf("noise: %w (bad message 1 static)", errDecrypt)
	}
	copy(remoteStatic[:], rsBytes)

	sss, err := keys.DH(localStatic, remoteStatic)
	if err != nil {
		return nil, nil, remoteStatic, nil, err
	}
	ss.mixKey(sss)

	payload1, err := ss.decryptAndHash(buf[keySize+keySize+tagSize:])
	if err != nil {
		return nil, nil, remoteStatic, nil, fmt.Errorf("noise: %w (bad message 1 payload)", errDecrypt)
	}

	// Authorize the peer by its static public key and obtain its PSK + response.
	psk, response, ok := auth(remoteStatic)
	if !ok {
		return nil, nil, remoteStatic, payload1, fmt.Errorf("noise: peer not authorized")
	}

	// -> message 2: e, ee, se, psk, payload
	fPriv, fPub, frep, err := newRepresentableEphemeral()
	if err != nil {
		return nil, nil, remoteStatic, payload1, err
	}
	ss.mixHash(fPub[:])
	msg := append([]byte(nil), frep[:]...)

	ee, err := keys.DH(fPriv, rePub)
	if err != nil {
		return nil, nil, remoteStatic, payload1, err
	}
	ss.mixKey(ee)

	se, err := keys.DH(fPriv, remoteStatic)
	if err != nil {
		return nil, nil, remoteStatic, payload1, err
	}
	ss.mixKey(se)

	ss.mixKeyAndHash(psk[:])

	encP2, err := ss.encryptAndHash(response)
	if err != nil {
		return nil, nil, remoteStatic, payload1, err
	}
	msg = append(msg, encP2...)

	if err := exch.sendMsg(msg); err != nil {
		return nil, nil, remoteStatic, payload1, err
	}

	c1, c2 := ss.split()
	// c2: responder->initiator (send), c1: initiator->responder (recv)
	return c2, c1, remoteStatic, payload1, nil
}

// msgExchanger abstracts sending/receiving a whole handshake message, so the
// same handshake logic runs over a byte stream (length-framed) or over
// datagrams (one message per packet).
type msgExchanger interface {
	sendMsg(msg []byte) error
	recvMsg() ([]byte, error)
}

type streamExchanger struct{ conn net.Conn }

func (s streamExchanger) sendMsg(m []byte) error   { return writeFrame(s.conn, m) }
func (s streamExchanger) recvMsg() ([]byte, error) { return readFrame(s.conn) }

// randPad returns a random number of random padding bytes in [0, max].
func randPad(max int) []byte {
	if max <= 0 {
		return nil
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	n := int(binary.BigEndian.Uint16(b[:])) % (max + 1)
	if n == 0 {
		return nil
	}
	pad := make([]byte, n)
	_, _ = rand.Read(pad)
	return pad
}
