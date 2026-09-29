// Package config builds the node configuration entirely from environment
// variables (there are no config files). See LoadNode for the recognised
// variables, and the README for a full reference.
package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

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
	SNI      string `json:"sni,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
}

// Peer is another node (or a road-warrior client) this node exchanges traffic
// with. The same description serves both directions: the peer may connect to
// us, and if Endpoint is set we connect to it as well. Peers come from the
// environment (GOPROXY_PEER_<NAME>_*) or, when managed in the web UI, from
// the data directory's peers.json.
type Peer struct {
	Name      string   `json:"name"`
	PublicKey string   `json:"public_key"`
	Routes    []string `json:"routes,omitempty"`   // IPv4 CIDRs behind the peer (destinations and allowed sources)
	IP        string   `json:"ip,omitempty"`       // tunnel IP handed to the peer when it connects; empty = none
	Endpoint  string   `json:"endpoint,omitempty"` // host:port to connect to; empty = only accept the peer
	NAT       bool     `json:"nat,omitempty"`      // translate clients' traffic to the peer to the node's address
	Disabled  bool     `json:"disabled,omitempty"` // kept in the configuration, but not used

	Transport    string          `json:"transport,omitempty"` // transport used to connect to Endpoint
	PSK          string          `json:"psk,omitempty"`
	TLS          TLSClientConfig `json:"tls,omitempty"`
	KeepaliveSec int             `json:"keepalive,omitempty"`
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
	PrivateKey string // empty: kept in DataDir (generated on first start)
	Name       string // this node's name, used in configs generated for peers
	DataDir    string // where web-managed peers and a generated key are kept; empty = none

	WebListen   string // address of the web UI; empty = off
	WebPassword string
	WebTLS      bool // serve the web UI over HTTPS with a self-signed certificate

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

	// Defaults for peer fields a peer leaves empty.
	DefaultPSK       string
	DefaultSNI       string
	DefaultInsecure  bool
	DefaultKeepalive int

	Peers []Peer // from the environment

	// Sources tells, for each of EditableSettings, where its value came from:
	// "env" (read-only in the web UI), "settings" (settings.json) or "default".
	Sources map[string]string
}

// ApplyDefaults fills a peer's empty fields from the node's defaults (TLS
// Insecure is a plain flag and is left as it is).
func (c *NodeConfig) ApplyDefaults(p *Peer) {
	if p.Transport == "" {
		p.Transport = c.Transport
	}
	if p.PSK == "" {
		p.PSK = c.DefaultPSK
	}
	if p.TLS.SNI == "" {
		p.TLS.SNI = c.DefaultSNI
	}
	if p.KeepaliveSec == 0 {
		p.KeepaliveSec = c.DefaultKeepalive
	}
}

// ParsePrivateKey returns the node's static private key.
func (c *NodeConfig) ParsePrivateKey() (keys.PrivateKey, error) {
	return keys.ParsePrivateKey(c.PrivateKey)
}

// EditableSettings are the node settings the web UI may set. A value from
// the environment takes precedence and is read-only there; otherwise the
// data directory's settings.json supplies it.
var EditableSettings = []string{
	"GOPROXY_NAME",
	"GOPROXY_LISTEN",
	"GOPROXY_TRANSPORT",
	"GOPROXY_PSK",
	"GOPROXY_TLS_HOST",
	"GOPROXY_TUN_ADDRESS",
	"GOPROXY_PUSH_ROUTES",
	"GOPROXY_MASQUERADE",
	"GOPROXY_MASQUERADE_IPS",
	"GOPROXY_LOG_CONNECTIONS",
}

// --- env helpers ---

var (
	loadMu  sync.Mutex        // serialises loads, which share overlay
	overlay map[string]string // settings.json during a load
)

// lookup returns a setting from the environment or, failing that, from the
// settings being loaded.
func lookup(key string) (string, bool) {
	if v, ok := os.LookupEnv(key); ok {
		return v, true
	}
	v, ok := overlay[key]
	return v, ok
}

func env(key, def string) string {
	if v, ok := lookup(key); ok {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := lookup(key)
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
	v, ok := lookup(key)
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

// peerNames scans the environment for GOPROXY_PEER_<NAME>_PUBLIC_KEY, which
// declares a peer. Names are returned sorted for determinism.
func peerNames() []string {
	var names []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		rest, ok := strings.CutPrefix(k, "GOPROXY_PEER_")
		if !ok {
			continue
		}
		if name, ok := strings.CutSuffix(rest, "_PUBLIC_KEY"); ok && name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// LoadNode builds the node config from the environment and, for the settings
// the environment leaves unset, the data directory's settings.json. Each peer
// is declared by GOPROXY_PEER_<NAME>_PUBLIC_KEY plus optional
// GOPROXY_PEER_<NAME>_<FIELD> variables; unset fields fall back to the global
// GOPROXY_* defaults.
func LoadNode() (*NodeConfig, error) {
	var settings map[string]string
	if dir := strings.TrimSpace(os.Getenv("GOPROXY_DATA_DIR")); dir != "" {
		var err error
		if settings, err = ReadSettings(dir); err != nil {
			return nil, err
		}
	}
	return LoadNodeWith(settings)
}

// LoadNodeWith is LoadNode with the given settings in place of settings.json,
// e.g. to check settings before saving them.
func LoadNodeWith(settings map[string]string) (*NodeConfig, error) {
	loadMu.Lock()
	defer loadMu.Unlock()
	overlay = map[string]string{}
	for _, k := range EditableSettings {
		if v, ok := settings[k]; ok {
			overlay[k] = v
		}
	}
	defer func() { overlay = nil }()

	c := &NodeConfig{
		PrivateKey:    strings.TrimSpace(env("GOPROXY_PRIVATE_KEY", "")),
		Name:          strings.TrimSpace(env("GOPROXY_NAME", "")),
		DataDir:       strings.TrimSpace(env("GOPROXY_DATA_DIR", "")),
		WebListen:     strings.TrimSpace(env("GOPROXY_WEB_LISTEN", "")),
		WebPassword:   env("GOPROXY_WEB_PASSWORD", ""),
		WebTLS:        envBool("GOPROXY_WEB_TLS", false),
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

	c.DefaultPSK = env("GOPROXY_PSK", "")
	c.DefaultSNI = env("GOPROXY_TLS_SNI", "")
	c.DefaultInsecure = envBool("GOPROXY_TLS_INSECURE", false)
	c.DefaultKeepalive = envInt("GOPROXY_KEEPALIVE", 25)
	if c.Name == "" {
		c.Name = defaultName()
	}
	c.Sources = map[string]string{}
	for _, k := range EditableSettings {
		switch _, inEnv := os.LookupEnv(k); {
		case inEnv:
			c.Sources[k] = "env"
		case overlay[k] != "":
			c.Sources[k] = "settings"
		default:
			c.Sources[k] = "default"
		}
	}

	for _, name := range peerNames() {
		base := "GOPROXY_PEER_" + name
		p := Peer{
			Name:      name,
			PublicKey: strings.TrimSpace(env(base+"_PUBLIC_KEY", "")),
			Routes:    splitList(env(base+"_ROUTES", "")),
			IP:        strings.TrimSpace(env(base+"_IP", "")),
			Endpoint:  strings.TrimSpace(env(base+"_ENDPOINT", "")),
			NAT:       envBool(base+"_NAT", false),
			Disabled:  envBool(base+"_DISABLED", false),
			Transport: env(base+"_TRANSPORT", ""),
			PSK:       env(base+"_PSK", ""),
			TLS: TLSClientConfig{
				SNI:      env(base+"_SNI", ""),
				Insecure: envBool(base+"_INSECURE", c.DefaultInsecure),
			},
			KeepaliveSec: envInt(base+"_KEEPALIVE", 0),
		}
		c.ApplyDefaults(&p)
		c.Peers = append(c.Peers, p)
	}
	return c, c.validate()
}

// defaultName derives a node name from the hostname: upper case, letters,
// digits, '-' and '_' only.
func defaultName() string {
	h, _ := os.Hostname()
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return -1
	}, strings.Split(h, ".")[0])
	if name == "" {
		return "NODE"
	}
	return name
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
	if c.PrivateKey != "" || c.DataDir == "" {
		if _, err := c.ParsePrivateKey(); err != nil {
			return fmt.Errorf("GOPROXY_PRIVATE_KEY: %w (or set GOPROXY_DATA_DIR to keep a generated one)", err)
		}
	}
	if c.WebListen != "" {
		if _, _, err := net.SplitHostPort(c.WebListen); err != nil {
			return fmt.Errorf("GOPROXY_WEB_LISTEN %q: %w", c.WebListen, err)
		}
		if c.WebPassword == "" {
			return fmt.Errorf("GOPROXY_WEB_PASSWORD is required with GOPROXY_WEB_LISTEN")
		}
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
	if err := ValidatePeers(c.Peers); err != nil {
		return err
	}
	// Without the web UI the environment must give the node something to do.
	if c.WebListen == "" {
		if len(c.Peers) == 0 && c.DataDir == "" {
			return fmt.Errorf("no peers configured (set GOPROXY_PEER_<NAME>_PUBLIC_KEY)")
		}
		dialing := false
		for _, p := range c.Peers {
			dialing = dialing || p.Endpoint != ""
		}
		if c.Listen == "" && !dialing && c.DataDir == "" {
			return fmt.Errorf("nothing to do: set GOPROXY_LISTEN and/or a peer's _ENDPOINT")
		}
	}
	return nil
}

// ValidPeerName reports whether name can name a peer: letters, digits, '-'
// and '_', at most 32 characters.
func ValidPeerName(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ValidatePeers checks a set of peers on its own and against each other:
// names and keys are unique, and a prefix belongs to one enabled peer only
// (a disabled peer may share its routes, e.g. as a standby).
func ValidatePeers(peers []Peer) error {
	owner := map[netip.Prefix]string{}
	keyOwner := map[keys.PublicKey]string{}
	names := map[string]bool{}
	for i := range peers {
		p := &peers[i]
		if !ValidPeerName(p.Name) {
			return fmt.Errorf("peer name %q: use letters, digits, '-' and '_' (up to 32)", p.Name)
		}
		if names[p.Name] {
			return fmt.Errorf("peer %q is defined twice", p.Name)
		}
		names[p.Name] = true
		pub, err := p.ParsePublicKey()
		if err != nil {
			return fmt.Errorf("peer %q: public key: %w", p.Name, err)
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
			return fmt.Errorf("peer %q: needs routes and/or an IP", p.Name)
		}
		for _, pfx := range prefixes {
			if p.Disabled {
				break
			}
			if other, ok := owner[pfx]; ok {
				return fmt.Errorf("route %s is set on both peer %q and %q", pfx, other, p.Name)
			}
			owner[pfx] = p.Name
		}

		if p.Endpoint != "" {
			if _, _, err := net.SplitHostPort(p.Endpoint); err != nil {
				return fmt.Errorf("peer %q endpoint %q: %w", p.Name, p.Endpoint, err)
			}
			if !validTransport(p.Transport) {
				return fmt.Errorf("peer %q: transport must be aead, tls or udp", p.Name)
			}
		}
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

// settingsFile holds, in the data directory, the settings made in the web UI.
const settingsFile = "settings.json"

// ReadSettings returns the settings saved in dir (none if there is no file).
func ReadSettings(dir string) (map[string]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, settingsFile))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, settingsFile), err)
	}
	return m, nil
}

// WriteSettings saves settings in dir (mode 0600: the PSK is among them).
// Only EditableSettings with a non-empty value are kept.
func WriteSettings(dir string, settings map[string]string) error {
	m := map[string]string{}
	for _, k := range EditableSettings {
		if v := strings.TrimSpace(settings[k]); v != "" {
			m[k] = v
		}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+settingsFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, settingsFile))
}

// SettingValues returns the value in effect of each of EditableSettings, as
// it would be written in the environment.
func (c *NodeConfig) SettingValues() map[string]string {
	return map[string]string{
		"GOPROXY_NAME":            c.Name,
		"GOPROXY_LISTEN":          c.Listen,
		"GOPROXY_TRANSPORT":       c.Transport,
		"GOPROXY_PSK":             c.DefaultPSK,
		"GOPROXY_TLS_HOST":        c.TLS.Host,
		"GOPROXY_TUN_ADDRESS":     c.Address,
		"GOPROXY_PUSH_ROUTES":     c.PushRoutes,
		"GOPROXY_MASQUERADE":      c.Masquerade,
		"GOPROXY_MASQUERADE_IPS":  strings.Join(c.MasqueradeIPs, " "),
		"GOPROXY_LOG_CONNECTIONS": strconv.FormatBool(c.LogConns),
	}
}

// Files that let a settings change made in the web UI be undone if the node
// then fails to start with it.
const (
	settingsPrev    = "settings.prev.json"
	settingsPending = "settings.pending"
)

// BeginSettingsChange saves settings, keeping the current ones to fall back
// to, and marks the change as pending until ConfirmSettings.
func BeginSettingsChange(dir string, settings map[string]string) error {
	cur, err := ReadSettings(dir)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(cur)
	if err := os.WriteFile(filepath.Join(dir, settingsPrev), b, 0o600); err != nil {
		return err
	}
	if err := WriteSettings(dir, settings); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, settingsPending), nil, 0o600)
}

// SettingsPending reports whether a settings change awaits confirmation.
func SettingsPending(dir string) bool {
	if dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, settingsPending))
	return err == nil
}

// ConfirmSettings accepts a pending change: the node started with it.
func ConfirmSettings(dir string) {
	os.Remove(filepath.Join(dir, settingsPending))
	os.Remove(filepath.Join(dir, settingsPrev))
}

// RollbackSettings undoes a pending change, restoring the previous settings.
func RollbackSettings(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, settingsPrev))
	if err != nil {
		return err
	}
	prev := map[string]string{}
	if err := json.Unmarshal(b, &prev); err != nil {
		return err
	}
	if err := WriteSettings(dir, prev); err != nil {
		return err
	}
	ConfirmSettings(dir)
	return nil
}
