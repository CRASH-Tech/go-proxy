// Package protocol defines the small JSON payloads exchanged inside the noise
// handshake: the client announces itself, and the server returns the tunnel
// parameters (assigned IP, subnet, MTU).
package protocol

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"
)

// ClientHello is sent by the client in handshake message 1.
type ClientHello struct {
	Timestamp int64  `json:"ts"`
	Name      string `json:"name,omitempty"`
	Pad       []byte `json:"pad,omitempty"` // random bytes to vary message length
}

// ServerHello is returned by the server in handshake message 2.
type ServerHello struct {
	ClientIP string `json:"client_ip"`
	ServerIP string `json:"server_ip"`
	Subnet   string `json:"subnet"`
	MTU      int    `json:"mtu"`
	Pad      []byte `json:"pad,omitempty"`
}

// AllowedClockSkew bounds how far a ClientHello timestamp may be from now.
const AllowedClockSkew = 90 * time.Second

func randBytes(max int) []byte {
	var l [1]byte
	_, _ = rand.Read(l[:])
	n := int(l[0]) % (max + 1)
	if n == 0 {
		return nil
	}
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// NewClientHello builds a ClientHello with the current timestamp and random pad.
func NewClientHello(name string) *ClientHello {
	return &ClientHello{Timestamp: time.Now().Unix(), Name: name, Pad: randBytes(200)}
}

// Marshal serialises a ClientHello.
func (h *ClientHello) Marshal() []byte { b, _ := json.Marshal(h); return b }

// Validate checks the timestamp against the allowed clock skew (anti-replay).
func (h *ClientHello) Validate() error {
	now := time.Now().Unix()
	diff := now - h.Timestamp
	if diff < 0 {
		diff = -diff
	}
	if time.Duration(diff)*time.Second > AllowedClockSkew {
		return fmt.Errorf("clienthello timestamp out of range (%ds)", diff)
	}
	return nil
}

// ParseClientHello deserialises a ClientHello.
func ParseClientHello(b []byte) (*ClientHello, error) {
	h := &ClientHello{}
	if err := json.Unmarshal(b, h); err != nil {
		return nil, fmt.Errorf("parse client hello: %w", err)
	}
	return h, nil
}

// NewServerHello builds a ServerHello with random pad.
func NewServerHello(clientIP, serverIP, subnet string, mtu int) *ServerHello {
	return &ServerHello{ClientIP: clientIP, ServerIP: serverIP, Subnet: subnet, MTU: mtu, Pad: randBytes(200)}
}

// Marshal serialises a ServerHello.
func (h *ServerHello) Marshal() []byte { b, _ := json.Marshal(h); return b }

// ParseServerHello deserialises a ServerHello.
func ParseServerHello(b []byte) (*ServerHello, error) {
	h := &ServerHello{}
	if err := json.Unmarshal(b, h); err != nil {
		return nil, fmt.Errorf("parse server hello: %w", err)
	}
	return h, nil
}
