// Package fallback handles connections that reach the server but fail to
// authenticate as a tunnel client — port scanners, and especially active
// probing by censorship systems. Instead of hanging or resetting (a proxy
// fingerprint in itself), the server behaves like an ordinary web server:
// returns a canned HTTP status, redirects, or transparently reverse-proxies to
// a real backend site. This makes the endpoint hard to distinguish from a
// normal website.
package fallback

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// Mode is the fallback behaviour.
type Mode int

const (
	// Off disables the fallback (the connection is simply closed).
	Off Mode = iota
	// Status returns a fixed HTTP status (e.g. 403).
	Status
	// Redirect returns an HTTP 302 to a URL.
	Redirect
	// Proxy transparently reverse-proxies to a real backend.
	Proxy
)

// Handler serves non-client connections.
type Handler struct {
	mode   Mode
	status int
	url    string
	target string
}

// New builds a Handler from configuration. mode is off|status|redirect|proxy.
// It returns (nil, nil) when the fallback is disabled.
func New(mode string, status int, url, target string) (*Handler, error) {
	switch mode {
	case "", "off", "close":
		return nil, nil
	case "status":
		if status == 0 {
			status = http.StatusForbidden
		}
		return &Handler{mode: Status, status: status}, nil
	case "redirect":
		if url == "" {
			return nil, fmt.Errorf("fallback redirect: URL is required")
		}
		return &Handler{mode: Redirect, url: url}, nil
	case "proxy":
		if target == "" {
			return nil, fmt.Errorf("fallback proxy: target is required")
		}
		if _, _, err := net.SplitHostPort(target); err != nil {
			return nil, fmt.Errorf("fallback proxy target %q: %w", target, err)
		}
		return &Handler{mode: Proxy, target: target}, nil
	default:
		return nil, fmt.Errorf("unknown fallback mode %q", mode)
	}
}

// Describe returns a short human-readable description for logs.
func (h *Handler) Describe() string {
	switch h.mode {
	case Status:
		return fmt.Sprintf("status %d", h.status)
	case Redirect:
		return "redirect " + h.url
	case Proxy:
		return "proxy -> " + h.target
	}
	return "off"
}

// Serve handles one non-client connection and closes it. conn must already
// replay any bytes that were consumed from the socket during the failed
// handshake, so a reverse-proxy backend sees the client's original request.
func (h *Handler) Serve(conn net.Conn) {
	defer conn.Close()
	switch h.mode {
	case Status:
		drain(conn)
		writeStatus(conn, h.status)
	case Redirect:
		drain(conn)
		writeRedirect(conn, h.url)
	case Proxy:
		h.serveProxy(conn)
	}
}

// drain best-effort reads the client's pending request so we don't reply into
// an unread stream (which some clients treat as a reset).
func drain(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Read(make([]byte, 4096))
	_ = conn.SetReadDeadline(time.Time{})
}

func nginxBody(title string) string {
	return fmt.Sprintf("<html>\r\n<head><title>%s</title></head>\r\n<body>\r\n"+
		"<center><h1>%s</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n",
		title, title)
}

func writeStatus(conn net.Conn, status int) {
	text := http.StatusText(status)
	if text == "" {
		status, text = http.StatusForbidden, "Forbidden"
	}
	body := nginxBody(fmt.Sprintf("%d %s", status, text))
	fmt.Fprintf(conn,
		"HTTP/1.1 %d %s\r\nServer: nginx\r\nDate: %s\r\nContent-Type: text/html\r\n"+
			"Content-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, text, httpDate(), len(body), body)
}

func writeRedirect(conn net.Conn, url string) {
	body := nginxBody("302 Found")
	fmt.Fprintf(conn,
		"HTTP/1.1 302 Found\r\nServer: nginx\r\nDate: %s\r\nLocation: %s\r\n"+
			"Content-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		httpDate(), url, len(body), body)
}

func httpDate() string { return time.Now().UTC().Format(http.TimeFormat) }

func (h *Handler) serveProxy(conn net.Conn) {
	backend, err := net.DialTimeout("tcp", h.target, 10*time.Second)
	if err != nil {
		log.Printf("fallback proxy dial %s: %v", h.target, err)
		writeStatus(conn, http.StatusBadGateway)
		return
	}
	defer backend.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(backend, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, backend); done <- struct{}{} }()
	<-done
	// Unblock the other direction, then wait for it to finish.
	conn.Close()
	backend.Close()
	<-done
}
