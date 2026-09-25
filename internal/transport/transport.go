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
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"goproxy/internal/sockopt"
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

// ClientDialer returns the dialer for the client's outer connections over
// network ("tcp" or "udp"). Its sockets -- and those of the DNS resolver used to
// look up the server's address -- are tagged with SO_MARK mark (0 = none), so
// the client's policy routing keeps them off its own TUN.
func ClientDialer(network string, mark int) *net.Dialer {
	ctl := sockopt.TCPControl
	if network == "udp" {
		ctl = sockopt.UDPControl
	}
	resolverDialer := &net.Dialer{Control: sockopt.MarkedControl(mark, nil)}
	return &net.Dialer{
		Timeout: 15 * time.Second,
		Control: sockopt.MarkedControl(mark, ctl),
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     resolverDialer.DialContext,
		},
	}
}

// --- aead (raw TCP) ---

type tcpTransport struct {
	dialer *net.Dialer
}

// NewTCP returns a raw-TCP transport (used with the "aead" mode) for listening.
func NewTCP() Transport { return tcpTransport{dialer: ClientDialer("tcp", 0)} }

// NewTCPClient returns a raw-TCP transport whose sockets carry SO_MARK mark.
func NewTCPClient(mark int) Transport { return tcpTransport{dialer: ClientDialer("tcp", mark)} }

func (t tcpTransport) Dial(addr string) (net.Conn, error) {
	c, err := t.dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	tuneTCP(c)
	return c, nil
}

func (tcpTransport) Listen(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: sockopt.TCPControl}
	return lc.Listen(context.Background(), "tcp", addr)
}

// --- tls ---

type tlsClientTransport struct {
	cfg    *tls.Config
	dialer *net.Dialer
}

// NewTLSClient returns a TLS transport for the client. sni sets the SNI/ServerName
// (leave empty to skip). insecure disables certificate verification (needed for
// self-signed server certs). Sockets carry SO_MARK mark (0 = none).
func NewTLSClient(sni string, insecure bool, mark int) Transport {
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	return tlsClientTransport{cfg: cfg, dialer: ClientDialer("tcp", mark)}
}

func (t tlsClientTransport) Dial(addr string) (net.Conn, error) {
	c, err := tls.DialWithDialer(t.dialer, "tcp", addr, t.cfg)
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
	lc := net.ListenConfig{Control: sockopt.TCPControl}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(ln, t.cfg), nil
}
