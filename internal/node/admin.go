package node

import (
	"fmt"
	"log"
	"net/netip"
	"slices"
	"time"

	"goproxy/internal/config"
	"goproxy/internal/flowlog"
	"goproxy/internal/keys"
)

// This file is the node's side of the web UI: what it shows and what it can
// change.

// Info describes this node.
type Info struct {
	Name           string `json:"name"`
	PublicKey      string `json:"public_key"`
	KeySource      string `json:"key_source"` // "env" (read-only) or "file"
	TunAddress     string `json:"tun_address"`
	TunNetwork     string `json:"tun_network"`
	Listen         string `json:"listen,omitempty"`
	Transport      string `json:"transport"`
	SelfSignedTLS  bool   `json:"self_signed_tls"` // tls listener without a real certificate
	MTU            int    `json:"mtu"`
	PushRoutes     string `json:"push_routes"`
	Masquerade     string `json:"masquerade,omitempty"`
	LogConnections bool   `json:"log_connections"`
	Editable       bool   `json:"editable"` // a data directory is set
	PSK            string `json:"psk,omitempty"`
}

// PeerInfo is a peer's configuration, where it comes from and its sessions
// (none while it is disabled).
type PeerInfo struct {
	config.Peer
	Source      string     `json:"source"`                 // "env" (read-only) or "file"
	InterfaceUp bool       `json:"interface_up,omitempty"` // its own TUN exists
	Links       []LinkInfo `json:"links"`
}

// LinkInfo describes one established session with a peer.
type LinkInfo struct {
	Direction string     `json:"direction"` // "out": we connected; "in": the peer did
	Remote    string     `json:"remote"`
	Since     time.Time  `json:"since"`
	TunnelIP  string     `json:"tunnel_ip,omitempty"` // the IP the peer handed to us
	RxBytes   uint64     `json:"rx_bytes"`
	TxBytes   uint64     `json:"tx_bytes"`
	LastRx    *time.Time `json:"last_rx,omitempty"`
}

// Info returns a description of this node.
func (n *Node) Info() Info {
	return Info{
		Name:           n.cfg.Name,
		PublicKey:      n.privKey().Public().String(),
		KeySource:      n.keySource,
		TunAddress:     n.cfg.Address,
		TunNetwork:     n.tunNet,
		Listen:         n.cfg.Listen,
		Transport:      n.cfg.Transport,
		SelfSignedTLS:  n.cfg.Transport == "tls" && n.cfg.TLS.Cert == "",
		MTU:            n.cfg.MTU,
		PushRoutes:     n.cfg.PushRoutes,
		Masquerade:     n.cfg.Masquerade,
		LogConnections: n.cfg.LogConns,
		Editable:       n.cfg.DataDir != "",
		PSK:            n.cfg.DefaultPSK,
	}
}

// Peers returns every configured peer, disabled ones included, with its
// sessions; the environment's first.
func (n *Node) Peers() []PeerInfo {
	n.mu.Lock()
	type src struct {
		cfg    config.Peer
		source string
	}
	var all []src
	for _, p := range n.cfg.Peers {
		all = append(all, src{p, "env"})
	}
	for _, p := range n.filePeers {
		n.cfg.ApplyDefaults(&p)
		all = append(all, src{p, "file"})
	}
	n.mu.Unlock()

	set := n.set.Load()
	out := make([]PeerInfo, 0, len(all))
	for _, s := range all {
		p := set.byName[s.cfg.Name]
		if p == nil || p.source != s.source {
			out = append(out, PeerInfo{Peer: s.cfg, Source: s.source, Links: []LinkInfo{}})
			continue
		}
		pi := PeerInfo{Peer: *p.conf(), Source: p.source, InterfaceUp: p.device() != nil, Links: []LinkInfo{}}
		p.mu.Lock()
		links := []*link{p.out, p.in}
		p.mu.Unlock()
		for _, l := range links {
			if l == nil {
				continue
			}
			li := LinkInfo{
				Direction: "in",
				Remote:    l.remote,
				Since:     l.since,
				RxBytes:   l.rx.Load(),
				TxBytes:   l.tx.Load(),
			}
			if l.outbound {
				li.Direction = "out"
			}
			if l.localIP != 0 {
				li.TunnelIP = netip.AddrFrom4(ip4(l.localIP)).String()
			}
			if ns := l.lastRx.Load(); ns != 0 {
				t := time.Unix(0, ns)
				li.LastRx = &t
			}
			pi.Links = append(pi.Links, li)
		}
		out = append(out, pi)
	}
	return out
}

// FilePeers returns the peers kept in the data directory, as stored.
func (n *Node) FilePeers() []config.Peer {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.filePeers)
}

// RegenerateKey replaces this node's key kept in the data directory with a
// new one. Every peer must then be given the new public key; sessions already
// up continue until they reconnect.
func (n *Node) RegenerateKey() (keys.PublicKey, error) {
	priv, err := keys.GeneratePrivateKey()
	if err != nil {
		return keys.PublicKey{}, err
	}
	return n.SetKey(priv)
}

// SetKey replaces this node's key kept in the data directory with priv (e.g.
// an existing key moved to this node), like RegenerateKey.
func (n *Node) SetKey(priv keys.PrivateKey) (keys.PublicKey, error) {
	if n.keySource != "file" {
		return keys.PublicKey{}, fmt.Errorf("the key comes from GOPROXY_PRIVATE_KEY; change it there")
	}
	if err := saveKey(n.cfg.DataDir, priv); err != nil {
		return keys.PublicKey{}, err
	}
	n.keyMu.Lock()
	n.priv = priv
	n.keyMu.Unlock()
	log.Printf("this node's key was replaced; new public key %s", priv.Public())
	return priv.Public(), nil
}

// NextFreeIP returns the first address of the TUN network not used by the
// node or handed to a peer, for a new client.
func (n *Node) NextFreeIP() (string, error) {
	pfx := netip.MustParsePrefix(n.tunNet)
	if pfx.Bits() > 30 {
		return "", fmt.Errorf("the TUN address %s has no room for clients: set GOPROXY_TUN_ADDRESS to a network, e.g. 10.8.0.1/24", n.cfg.Address)
	}
	// Taken: the node's address, and every peer prefix inside the TUN network
	// (a client's /32, a subnet routed to a site). Wider routes such as
	// 0.0.0.0/0 do not claim the pool.
	taken := []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4(n.tunIP), 32)}
	for _, p := range n.set.Load().peers {
		prefixes, _ := p.conf().Prefixes()
		for _, pp := range prefixes {
			if pp.Bits() >= pfx.Bits() && pfx.Contains(pp.Addr()) {
				taken = append(taken, pp)
			}
		}
	}
	last := lastAddr(pfx)
next:
	for ip := pfx.Addr().Next(); ip.IsValid() && ip.Less(last); ip = ip.Next() {
		for _, tp := range taken {
			if tp.Contains(ip) {
				continue next
			}
		}
		return ip.String(), nil
	}
	return "", fmt.Errorf("no free address left in %s", pfx)
}

// lastAddr returns the broadcast address of an IPv4 prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	v := u32(a) | (1<<(32-p.Bits()) - 1)
	return netip.AddrFrom4(ip4(v))
}

// Connections returns whether connections are logged and the recent ones.
func (n *Node) Connections() (bool, []flowlog.Entry) {
	if n.flows == nil {
		return false, nil
	}
	return true, n.flows.Recent()
}
