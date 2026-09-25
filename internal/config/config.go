// Package config builds the node configuration entirely from environment
// variables (there are no config files). See LoadNode for the recognised
// variables, and the README for a full reference.
package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/blake2s"

	"goproxy/internal/keys"
)

// TLSServerConfig configures the TLS transport of the listener.
type TLSServerConfig struct {
	Cert string // path to PEM cert; empty => self-signed
	Key  string // path to PEM key
	Host string // CN/SAN for a generated self-signed cert
}

// TLSClientConfig configures the TLS transport when connecting to a peer.
type TLSClientConfig struct {
	SNI      string
	Insecure bool
}

// Peer is another node (or a road-warrior client) this node exchanges traffic
// with. The same description serves both directions: the peer may connect to
// us, and if Endpoint is set we connect to it as well.
type Peer struct {
	Name      string // from the GOPROXY_PEER_<NAME> suffix
	PublicKey string
	Routes    []string // IPv4 CIDRs behind the peer (destinations and allowed sources)
	IP        string   // tunnel IP handed to the peer when it connects; empty = none
	Endpoint  string   // host:port to connect to; empty = only accept the peer
	NAT       bool     // translate clients' traffic to the peer to the node's address

	Transport    string // transport used to connect to Endpoint
	PSK          string
	TLS          TLSClientConfig
	KeepaliveSec int
}

// ParsePublicKey returns the peer's static public key.
func (p *Peer) ParsePublicKey() (keys.PublicKey, error) {
	return keys.ParsePublicKey(p.PublicKey)
}

// Prefixes returns the peer's routes, plus IP/32 when it is handed an IP.
func (p *Peer) Prefixes() ([]netip.Prefix, error) {
	var out []netip.Prefix
	if p.IP != "" {
		ip, err := netip.ParseAddr(p.IP)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("ip %q: need an IPv4 address", p.IP)
		}
		out = append(out, netip.PrefixFrom(ip, 32))
	}
	for _, cidr := range p.Routes {
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("route %q: %w", cidr, err)
		}
		if !pfx.Addr().Is4() {
			return nil, fmt.Errorf("route %q: only IPv4 routes are supported", cidr)
		}
		out = append(out, pfx.Masked())
	}
	return out, nil
}

// NodeConfig is the whole configuration of a node: its identity, its TUN, an
// optional listener and its peers.
type NodeConfig struct {
	PrivateKey string

	InterfaceName string   // TUN device name
	Address       string   // TUN address (IPv4 CIDR)
	MTU           int      // TUN MTU
	FwMark        int      // SO_MARK of the node's own connections to peers
	PushRoutes    string   // host routes for the peers' prefixes: false | true | clients
	Masquerade    string   // interface to masquerade out of; empty = off
	MasqueradeIPs []string // source networks to masquerade; empty = the TUN network
	LogConns      bool     // log every new connection through the tunnel

	Listen    string // empty => do not accept connections
	Transport string // listener transport: aead | tls | udp
	TLS       TLSServerConfig

	// Fallback for connections that fail the handshake (probes/scanners).
	FallbackMode   string // off | status | redirect | proxy
	FallbackStatus int    // HTTP status for "status" mode (default 403)
	FallbackURL    string // Location for "redirect" mode
	FallbackTarget string // host:port for "proxy" mode

	ObfsMaxPad int  // max random padding per record (traffic-analysis resistance)
	ObfsCover  bool // send randomised cover traffic

	Peers []Peer
}

// ParsePrivateKey returns the node's static private key.
func (c *NodeConfig) ParsePrivateKey() (keys.PrivateKey, error) {
	return keys.ParsePrivateKey(c.PrivateKey)
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

// peerNames scans the environment for GOPROXY_PEER_<NAME> base variables (the
// public key). A key is a base var iff the part after the prefix contains no
// underscore, so that field vars like GOPROXY_PEER_DC2_ROUTES are not mistaken
// for a peer named "DC2_ROUTES". Names are returned sorted for determinism.
func peerNames() []string {
	var names []string
	const prefix = "GOPROXY_PEER_"
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		rest, ok := strings.CutPrefix(k, prefix)
		if !ok || rest == "" || strings.Contains(rest, "_") {
			continue
		}
		names = append(names, rest)
	}
	sort.Strings(names)
	return names
}

// LoadNode builds the node config from the environment. Each peer is declared
// by GOPROXY_PEER_<NAME> (its public key) plus optional GOPROXY_PEER_<NAME>_<FIELD>
// variables; unset fields fall back to the global GOPROXY_* defaults.
func LoadNode() (*NodeConfig, error) {
	c := &NodeConfig{
		PrivateKey:    env("GOPROXY_PRIVATE_KEY", ""),
		InterfaceName: env("GOPROXY_IFNAME", "goproxy0"),
		Address:       env("GOPROXY_TUN_ADDRESS", "10.255.255.1/32"),
		MTU:           envInt("GOPROXY_MTU", 1320),
		PushRoutes:    pushRoutes(env("GOPROXY_PUSH_ROUTES", "")),
		Masquerade:    strings.TrimSpace(env("GOPROXY_MASQUERADE", "")),
		MasqueradeIPs: splitList(env("GOPROXY_MASQUERADE_IPS", "")),
		LogConns:      envBool("GOPROXY_LOG_CONNECTIONS", false),
		Listen:        env("GOPROXY_LISTEN", ""),
		Transport:     env("GOPROXY_TRANSPORT", "aead"),
		TLS: TLSServerConfig{
			Cert: env("GOPROXY_TLS_CERT", ""),
			Key:  env("GOPROXY_TLS_KEY", ""),
			Host: env("GOPROXY_TLS_HOST", "www.microsoft.com"),
		},
		FallbackMode:   env("GOPROXY_FALLBACK_MODE", "off"),
		FallbackStatus: envInt("GOPROXY_FALLBACK_STATUS", 403),
		FallbackURL:    env("GOPROXY_FALLBACK_URL", ""),
		FallbackTarget: env("GOPROXY_FALLBACK_TARGET", ""),
		ObfsMaxPad:     envInt("GOPROXY_OBFS_MAX_PAD", 255),
		ObfsCover:      envBool("GOPROXY_OBFS_COVER", true),
	}
	mark, err := strconv.ParseInt(strings.TrimSpace(env("GOPROXY_FWMARK", "0x676f")), 0, 32)
	if err != nil || mark <= 0 {
		return nil, fmt.Errorf("GOPROXY_FWMARK must be a positive integer")
	}
	c.FwMark = int(mark)

	gPSK := env("GOPROXY_PSK", "")
	gSNI := env("GOPROXY_TLS_SNI", "")
	gInsecure := envBool("GOPROXY_TLS_INSECURE", false)
	gKeepalive := envInt("GOPROXY_KEEPALIVE", 25)

	for _, name := range peerNames() {
		base := "GOPROXY_PEER_" + name
		c.Peers = append(c.Peers, Peer{
			Name:      name,
			PublicKey: strings.TrimSpace(env(base, "")),
			Routes:    splitList(env(base+"_ROUTES", "")),
			IP:        strings.TrimSpace(env(base+"_IP", "")),
			Endpoint:  strings.TrimSpace(env(base+"_ENDPOINT", "")),
			NAT:       envBool(base+"_NAT", false),
			Transport: env(base+"_TRANSPORT", c.Transport),
			PSK:       env(base+"_PSK", gPSK),
			TLS: TLSClientConfig{
				SNI:      env(base+"_SNI", gSNI),
				Insecure: envBool(base+"_INSECURE", gInsecure),
			},
			KeepaliveSec: envInt(base+"_KEEPALIVE", gKeepalive),
		})
	}
	return c, c.validate()
}

// pushRoutes normalises GOPROXY_PUSH_ROUTES: the usual boolean spellings map
// to "true"/"false"; "clients" is kept; anything else is returned for
// validate to reject.
func pushRoutes(v string) string {
	switch v = strings.ToLower(strings.TrimSpace(v)); v {
	case "", "0", "false", "no", "off", "n":
		return "false"
	case "1", "true", "yes", "on", "y":
		return "true"
	}
	return v
}

func validTransport(t string) bool { return t == "aead" || t == "tls" || t == "udp" }

func (c *NodeConfig) validate() error {
	if _, err := c.ParsePrivateKey(); err != nil {
		return fmt.Errorf("GOPROXY_PRIVATE_KEY: %w", err)
	}
	if c.InterfaceName == "" {
		return fmt.Errorf("GOPROXY_IFNAME is empty")
	}
	if p, err := netip.ParsePrefix(c.Address); err != nil || !p.Addr().Is4() {
		return fmt.Errorf("GOPROXY_TUN_ADDRESS %q: need an IPv4 CIDR, e.g. 10.8.0.1/24", c.Address)
	}
	if !validTransport(c.Transport) {
		return fmt.Errorf("GOPROXY_TRANSPORT must be aead, tls or udp")
	}
	if c.PushRoutes != "false" && c.PushRoutes != "true" && c.PushRoutes != "clients" {
		return fmt.Errorf("GOPROXY_PUSH_ROUTES must be false, true or clients")
	}
	if strings.ContainsAny(c.Masquerade, " \t/") || len(c.Masquerade) > 15 {
		return fmt.Errorf("GOPROXY_MASQUERADE %q: need an interface name, e.g. eth0", c.Masquerade)
	}
	if len(c.MasqueradeIPs) > 0 && c.Masquerade == "" {
		return fmt.Errorf("GOPROXY_MASQUERADE_IPS needs GOPROXY_MASQUERADE (the interface)")
	}
	for _, cidr := range c.MasqueradeIPs {
		if p, err := netip.ParsePrefix(cidr); err != nil || !p.Addr().Is4() {
			return fmt.Errorf("GOPROXY_MASQUERADE_IPS %q: need IPv4 CIDRs, e.g. 192.168.0.0/16", cidr)
		}
	}
	if err := c.validateFallback(); err != nil {
		return err
	}
	if len(c.Peers) == 0 {
		return fmt.Errorf("no peers configured (set GOPROXY_PEER_<NAME>=public_key)")
	}

	dialing := false
	owner := map[netip.Prefix]string{}
	keyOwner := map[keys.PublicKey]string{}
	for i := range c.Peers {
		p := &c.Peers[i]
		pub, err := p.ParsePublicKey()
		if err != nil {
			return fmt.Errorf("GOPROXY_PEER_%s: public key: %w", p.Name, err)
		}
		if other, ok := keyOwner[pub]; ok {
			return fmt.Errorf("peers %q and %q have the same public key", other, p.Name)
		}
		keyOwner[pub] = p.Name

		prefixes, err := p.Prefixes()
		if err != nil {
			return fmt.Errorf("peer %q: %w", p.Name, err)
		}
		if len(prefixes) == 0 {
			return fmt.Errorf("peer %q: set GOPROXY_PEER_%s_ROUTES and/or _IP", p.Name, p.Name)
		}
		for _, pfx := range prefixes {
			if other, ok := owner[pfx]; ok {
				return fmt.Errorf("route %s is set on both peer %q and %q", pfx, other, p.Name)
			}
			owner[pfx] = p.Name
		}

		if p.Endpoint != "" {
			dialing = true
			if _, _, err := net.SplitHostPort(p.Endpoint); err != nil {
				return fmt.Errorf("peer %q endpoint %q: %w", p.Name, p.Endpoint, err)
			}
			if !validTransport(p.Transport) {
				return fmt.Errorf("peer %q: transport must be aead, tls or udp", p.Name)
			}
		}
	}
	if c.Listen == "" && !dialing {
		return fmt.Errorf("nothing to do: set GOPROXY_LISTEN and/or a peer's _ENDPOINT")
	}
	return nil
}

func (c *NodeConfig) validateFallback() error {
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
