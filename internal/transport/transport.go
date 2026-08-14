// Package transport provides the outer byte-stream between client and server.
// Two modes are supported:
//
//   - "aead": a raw TCP connection. There is no framing of its own; the noise
//     session layered on top produces a stream that is indistinguishable from
//     random, which is the anti-DPI property for this mode.
//   - "tls": a genuine TLS connection, so on-path inspection sees ordinary
//     HTTPS-looking traffic (real ClientHello, SNI, certificate).
//
// In both cases the same noise session (mutual auth + AEAD records) runs on top
// of the net.Conn returned here.
package transport

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// Transport dials or listens for the outer connection.
type Transport interface {
	Dial(addr string) (net.Conn, error)
	Listen(addr string) (net.Listener, error)
}

func tuneTCP(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

// --- aead (raw TCP) ---

type tcpTransport struct{}

// NewTCP returns a raw-TCP transport (used with the "aead" mode).
func NewTCP() Transport { return tcpTransport{} }

func (tcpTransport) Dial(addr string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, err
	}
	tuneTCP(c)
	return c, nil
}

func (tcpTransport) Listen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// --- tls ---

type tlsClientTransport struct {
	cfg *tls.Config
}

// NewTLSClient returns a TLS transport for the client. sni sets the SNI/ServerName
// (leave empty to skip). insecure disables certificate verification (needed for
// self-signed server certs).
func NewTLSClient(sni string, insecure bool) Transport {
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	return tlsClientTransport{cfg: cfg}
}

func (t tlsClientTransport) Dial(addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 15 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, t.cfg)
	if err != nil {
		return nil, err
	}
	tuneTCP(c.NetConn())
	return c, nil
}

func (tlsClientTransport) Listen(addr string) (net.Listener, error) {
	return nil, fmt.Errorf("tls client transport cannot listen")
}

type tlsServerTransport struct {
	cfg *tls.Config
}

// NewTLSServer returns a TLS transport for the server using the given certificate.
func NewTLSServer(cert tls.Certificate) Transport {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	return tlsServerTransport{cfg: cfg}
}

func (tlsServerTransport) Dial(addr string) (net.Conn, error) {
	return nil, fmt.Errorf("tls server transport cannot dial")
}

func (t tlsServerTransport) Listen(addr string) (net.Listener, error) {
	return tls.Listen("tcp", addr, t.cfg)
}
