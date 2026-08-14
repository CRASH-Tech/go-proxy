// Package config builds the server/client configuration entirely from
// environment variables (there are no config files). See LoadServer/LoadClient
// for the recognised variables, and the README for a full reference.
package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/blake2s"

	"goproxy/internal/keys"
)

// TunnelConfig describes the private tunnel network.
type TunnelConfig struct {
	Subnet   string // e.g. "10.8.0.0/24"
	ServerIP string // e.g. "10.8.0.1"
}

// TLSServerConfig configures the TLS transport on the server side.
type TLSServerConfig struct {
	Cert string // path to PEM cert; empty => self-signed
	Key  string // path to PEM key
	Host string // CN/SAN for a generated self-signed cert
}

// ClientEntry authorizes a single client by its static public key and assigns it
// a fixed tunnel IP.
type ClientEntry struct {
	Name       string
	PublicKey  string
	IP         string   // tunnel IP, e.g. "10.8.0.2"
	AllowedIPs []string // extra CIDRs routed to this client
}

// ServerConfig is the server role configuration.
type ServerConfig struct {
	Listen          string
	Transport       string // "aead" | "tls"
	PrivateKey      string
	PSK             string
	Tunnel          TunnelConfig
	MTU             int
	TLS             TLSServerConfig
	EgressInterface string // empty => autodetect
	AutoNAT         bool
	InterfaceName   string // TUN device name
	Clients         []ClientEntry

	ObfsMaxPad int  // max random padding per record (traffic-analysis resistance)
	ObfsCover  bool // send randomised cover traffic

	// Fallback for connections that fail the client handshake (probes/scanners).
	FallbackMode   string // off | status | redirect | proxy
	FallbackStatus int    // HTTP status for "status" mode (default 403)
	FallbackURL    string // Location for "redirect" mode
	FallbackTarget string // host:port for "proxy" mode
}

// TLSClientConfig configures the TLS transport on the client side.
type TLSClientConfig struct {
	SNI      string
	Insecure bool
}

// ServerConn describes one upstream server the client connects to.
type ServerConn struct {
	Name            string // from the GOPROXY_SERVER_<NAME> suffix
	Address         string // host:port
	Transport       string
	PrivateKey      string // this client's static private key for this server
	ServerPublicKey string
	PSK             string
	TLS             TLSClientConfig
	Routes          []string // CIDRs to route through this server (split tunnel)
	SetDefaultRoute bool     // route all traffic through this server
	Gateway         bool     // masquerade forwarded LAN traffic into this tunnel
	InterfaceName   string   // TUN device name
	KeepaliveSec    int
}

// ParsePrivateKey returns this server connection's client static private key.
func (s *ServerConn) ParsePrivateKey() (keys.PrivateKey, error) {
	return keys.ParsePrivateKey(s.PrivateKey)
}

// ParseServerPublicKey returns the server's static public key.
func (s *ServerConn) ParseServerPublicKey() (keys.PublicKey, error) {
	return keys.ParsePublicKey(s.ServerPublicKey)
}

// ClientConfig is the client role configuration: one or more servers plus
// shared settings.
type ClientConfig struct {
	Servers    []ServerConn
	MTU        int
	ObfsMaxPad int
	ObfsCover  bool
}

// --- env helpers ---

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on", "y":
		return true
	case "0", "false", "no", "off", "n":
		return false
	default:
		return def
	}
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

// splitList splits on commas and/or whitespace, dropping empty fields.
func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	var out []string
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// loadClients reads the authorized clients from GOPROXY_CLIENT_<NAME> variables.
// The client name is the suffix; the value is "public_key,ip[,allowed_ips]" with
// allowed_ips space-separated. Example:
//
//	GOPROXY_CLIENT_LAPTOP=pubA=,10.8.0.2
//	GOPROXY_CLIENT_PC=pubB=,10.8.0.3,192.168.50.0/24 10.0.0.0/8
func loadClients() ([]ClientEntry, error) {
	const prefix = "GOPROXY_CLIENT_"
	var out []ClientEntry
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		k, v := kv[:eq], kv[eq+1:]
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		name := k[len(prefix):]
		if name == "" {
			continue
		}
		fields := strings.Split(v, ",")
		if len(fields) < 2 {
			return nil, fmt.Errorf("%s: need public_key,ip[,allowed_ips]", k)
		}
		e := ClientEntry{
			Name:      name,
			PublicKey: strings.TrimSpace(fields[0]),
			IP:        strings.TrimSpace(fields[1]),
		}
		if len(fields) >= 3 {
			e.AllowedIPs = splitList(fields[2])
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// LoadServer builds the server config from the environment.
func LoadServer() (*ServerConfig, error) {
	c := &ServerConfig{
		Listen:     env("GOPROXY_LISTEN", ""),
		Transport:  env("GOPROXY_TRANSPORT", "aead"),
		PrivateKey: env("GOPROXY_PRIVATE_KEY", ""),
		PSK:        env("GOPROXY_PSK", ""),
		Tunnel: TunnelConfig{
			Subnet:   env("GOPROXY_TUNNEL_SUBNET", "10.8.0.0/24"),
			ServerIP: env("GOPROXY_TUNNEL_SERVER_IP", "10.8.0.1"),
		},
		MTU: envInt("GOPROXY_MTU", 1380),
		TLS: TLSServerConfig{
			Cert: env("GOPROXY_TLS_CERT", ""),
			Key:  env("GOPROXY_TLS_KEY", ""),
			Host: env("GOPROXY_TLS_HOST", "www.microsoft.com"),
		},
		EgressInterface: env("GOPROXY_EGRESS_INTERFACE", ""),
		AutoNAT:         envBool("GOPROXY_AUTO_NAT", true),
		InterfaceName:   env("GOPROXY_IFNAME", ""),
		FallbackMode:    env("GOPROXY_FALLBACK_MODE", "off"),
		FallbackStatus:  envInt("GOPROXY_FALLBACK_STATUS", 403),
		FallbackURL:     env("GOPROXY_FALLBACK_URL", ""),
		FallbackTarget:  env("GOPROXY_FALLBACK_TARGET", ""),
		ObfsMaxPad:      envInt("GOPROXY_OBFS_MAX_PAD", 255),
		ObfsCover:       envBool("GOPROXY_OBFS_COVER", true),
	}
	clients, err := loadClients()
	if err != nil {
		return nil, err
	}
	c.Clients = clients
	return c, c.validate()
}

// serverNames scans the environment for GOPROXY_SERVER_<NAME> base variables
// (the address). A key is a base var iff the part after the prefix contains no
// underscore, so that field vars like GOPROXY_SERVER_DE_ROUTES are not mistaken
// for a server named "DE_ROUTES". Names are returned sorted for determinism.
func serverNames() []string {
	seen := map[string]bool{}
	var names []string
	const prefix = "GOPROXY_SERVER_"
	for _, kv := range os.Environ() {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		k := kv[:eq]
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		rest := k[len(prefix):]
		if rest == "" || strings.Contains(rest, "_") {
			continue // a field var, not a base address var
		}
		if !seen[rest] {
			seen[rest] = true
			names = append(names, rest)
		}
	}
	sort.Strings(names)
	return names
}

// LoadClient builds the client config from the environment. Each server is
// declared by GOPROXY_SERVER_<NAME> (its address) plus optional
// GOPROXY_SERVER_<NAME>_<FIELD> variables; unset fields fall back to the global
// GOPROXY_* defaults.
func LoadClient() (*ClientConfig, error) {
	c := &ClientConfig{
		MTU:        envInt("GOPROXY_MTU", 1380),
		ObfsMaxPad: envInt("GOPROXY_OBFS_MAX_PAD", 255),
		ObfsCover:  envBool("GOPROXY_OBFS_COVER", true),
	}
	gTransport := env("GOPROXY_TRANSPORT", "aead")
	gPriv := env("GOPROXY_PRIVATE_KEY", "")
	gPSK := env("GOPROXY_PSK", "")
	gSNI := env("GOPROXY_TLS_SNI", "")
	gInsecure := envBool("GOPROXY_TLS_INSECURE", false)
	gGateway := envBool("GOPROXY_GATEWAY", false)
	gKeepalive := envInt("GOPROXY_KEEPALIVE", 25)

	for _, name := range serverNames() {
		base := "GOPROXY_SERVER_" + name
		c.Servers = append(c.Servers, ServerConn{
			Name:            name,
			Address:         env(base, ""),
			Transport:       env(base+"_TRANSPORT", gTransport),
			PrivateKey:      env(base+"_PRIVATE_KEY", gPriv),
			ServerPublicKey: env(base+"_PUBLIC_KEY", ""),
			PSK:             env(base+"_PSK", gPSK),
			TLS: TLSClientConfig{
				SNI:      env(base+"_SNI", gSNI),
				Insecure: envBool(base+"_INSECURE", gInsecure),
			},
			Routes:          splitList(env(base+"_ROUTES", "")),
			SetDefaultRoute: envBool(base+"_DEFAULT", false),
			Gateway:         envBool(base+"_GATEWAY", gGateway),
			InterfaceName:   env(base+"_IFNAME", ""),
			KeepaliveSec:    envInt(base+"_KEEPALIVE", gKeepalive),
		})
	}
	return c, c.validate()
}

func (c *ServerConfig) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("GOPROXY_LISTEN is required")
	}
	if c.Transport != "aead" && c.Transport != "tls" && c.Transport != "udp" {
		return fmt.Errorf("GOPROXY_TRANSPORT must be aead, tls or udp")
	}
	if _, err := c.ParsePrivateKey(); err != nil {
		return fmt.Errorf("GOPROXY_PRIVATE_KEY: %w", err)
	}
	if c.Tunnel.Subnet == "" || c.Tunnel.ServerIP == "" {
		return fmt.Errorf("GOPROXY_TUNNEL_SUBNET and GOPROXY_TUNNEL_SERVER_IP are required")
	}
	if _, _, err := net.ParseCIDR(c.Tunnel.Subnet); err != nil {
		return fmt.Errorf("GOPROXY_TUNNEL_SUBNET: %w", err)
	}
	if len(c.Clients) == 0 {
		return fmt.Errorf("no clients configured (set GOPROXY_CLIENT_<NAME>=pubkey,ip)")
	}
	for _, cl := range c.Clients {
		if cl.PublicKey == "" || cl.IP == "" {
			return fmt.Errorf("GOPROXY_CLIENT_%s: needs public_key,ip", cl.Name)
		}
		if _, err := keys.ParsePublicKey(cl.PublicKey); err != nil {
			return fmt.Errorf("GOPROXY_CLIENT_%s: %w", cl.Name, err)
		}
		if net.ParseIP(cl.IP) == nil {
			return fmt.Errorf("GOPROXY_CLIENT_%s: bad ip %q", cl.Name, cl.IP)
		}
		for _, cidr := range cl.AllowedIPs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("GOPROXY_CLIENT_%s allowed ip %q: %w", cl.Name, cidr, err)
			}
		}
	}
	switch c.FallbackMode {
	case "", "off", "close", "status":
	case "redirect":
		if c.FallbackURL == "" {
			return fmt.Errorf("GOPROXY_FALLBACK_URL is required for redirect mode")
		}
	case "proxy":
		if c.FallbackTarget == "" {
			return fmt.Errorf("GOPROXY_FALLBACK_TARGET is required for proxy mode")
		}
		if _, _, err := net.SplitHostPort(c.FallbackTarget); err != nil {
			return fmt.Errorf("GOPROXY_FALLBACK_TARGET %q: %w", c.FallbackTarget, err)
		}
	default:
		return fmt.Errorf("GOPROXY_FALLBACK_MODE must be off|status|redirect|proxy")
	}
	return nil
}

func (c *ClientConfig) validate() error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("no servers configured (set GOPROXY_SERVER_<NAME>=host:port)")
	}
	defaults := 0
	ifnames := map[string]string{}
	for i := range c.Servers {
		s := &c.Servers[i]
		if s.Address == "" {
			return fmt.Errorf("server %q: GOPROXY_SERVER_%s address is empty", s.Name, s.Name)
		}
		if s.Transport != "aead" && s.Transport != "tls" && s.Transport != "udp" {
			return fmt.Errorf("server %q: transport must be aead, tls or udp", s.Name)
		}
		if _, err := s.ParsePrivateKey(); err != nil {
			return fmt.Errorf("server %q private key: %w", s.Name, err)
		}
		if _, err := s.ParseServerPublicKey(); err != nil {
			return fmt.Errorf("server %q public key: %w", s.Name, err)
		}
		for _, cidr := range s.Routes {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("server %q route %q: %w", s.Name, cidr, err)
			}
		}
		if s.SetDefaultRoute {
			defaults++
		}
		if s.InterfaceName != "" {
			if other, ok := ifnames[s.InterfaceName]; ok {
				return fmt.Errorf("servers %q and %q share interface name %q", other, s.Name, s.InterfaceName)
			}
			ifnames[s.InterfaceName] = s.Name
		}
	}
	if defaults > 1 {
		return fmt.Errorf("only one server may set _DEFAULT=true (%d do)", defaults)
	}
	return nil
}

// ParsePrivateKey returns the server's static private key.
func (c *ServerConfig) ParsePrivateKey() (keys.PrivateKey, error) {
	return keys.ParsePrivateKey(c.PrivateKey)
}

// DerivePSK turns the configured PSK string into a 32-byte key. Empty yields an
// all-zero PSK (still a valid IKpsk2 key). A 32-byte base64 value is used as-is;
// anything else is treated as a passphrase and hashed with BLAKE2s.
func DerivePSK(s string) [32]byte {
	var out [32]byte
	if s == "" {
		return out
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		copy(out[:], b)
		return out
	}
	out = blake2s.Sum256([]byte("goproxy-psk:" + s))
	return out
}
