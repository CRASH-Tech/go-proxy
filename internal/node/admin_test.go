package node

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"goproxy/internal/config"
	"goproxy/internal/keys"
)

func pub(t *testing.T) string {
	t.Helper()
	k, err := keys.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.Public().String()
}

// testNode returns a node (not running: no TUN) with one peer from the
// environment and a data directory.
func testNode(t *testing.T) (*Node, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.NodeConfig{
		Name: "HOME", DataDir: dir, InterfaceName: "goproxy0", Address: "10.8.0.1/24",
		MTU: 1320, Transport: "udp", PushRoutes: "false", FwMark: 0x676f,
		DefaultKeepalive: 25, DefaultPSK: "s",
	}
	envPeer := config.Peer{Name: "EXIT", PublicKey: pub(t), Routes: []string{"0.0.0.0/0"}}
	cfg.ApplyDefaults(&envPeer)
	cfg.Peers = []config.Peer{envPeer}
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return n, dir
}

func TestKeyGeneratedAndKept(t *testing.T) {
	n, dir := testNode(t)
	if n.Info().KeySource != "file" {
		t.Fatal("key not from the data directory")
	}
	first := n.Info().PublicKey
	n2, err := New(n.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if n2.Info().PublicKey != first {
		t.Fatal("a restart generated another key")
	}
	if st, err := os.Stat(filepath.Join(dir, keyFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	newPub, err := n.RegenerateKey()
	if err != nil || newPub.String() == first || n.Info().PublicKey != newPub.String() {
		t.Fatalf("regenerate: %v", err)
	}
}

func TestSetFilePeers(t *testing.T) {
	n, dir := testNode(t)
	laptop := config.Peer{Name: "LAPTOP", PublicKey: pub(t), IP: "10.8.0.2"}
	if err := n.SetFilePeers([]config.Peer{laptop}); err != nil {
		t.Fatal(err)
	}
	peers := n.Peers()
	if len(peers) != 2 || peers[0].Source != "env" || peers[1].Source != "file" {
		t.Fatalf("peers = %+v", peers)
	}
	if peers[1].Transport != "udp" || peers[1].KeepaliveSec != 25 || peers[1].PSK != "s" {
		t.Fatalf("defaults not applied to a file peer: %+v", peers[1].Peer)
	}
	// Saved as entered (without defaults) and read back on start.
	b, _ := os.ReadFile(filepath.Join(dir, peersFile))
	if !strings.Contains(string(b), `"LAPTOP"`) || strings.Contains(string(b), `"keepalive"`) {
		t.Fatalf("peers.json = %s", b)
	}
	n2, err := New(n.cfg)
	if err != nil || len(n2.Peers()) != 2 {
		t.Fatalf("reload: %v, %d peers", err, len(n2.Peers()))
	}

	// Unchanged peers keep their object (and so their sessions).
	before := n.set.Load().byName
	phone := config.Peer{Name: "PHONE", PublicKey: pub(t), IP: "10.8.0.3"}
	if err := n.SetFilePeers([]config.Peer{laptop, phone}); err != nil {
		t.Fatal(err)
	}
	after := n.set.Load().byName
	if after["LAPTOP"] != before["LAPTOP"] || after["EXIT"] != before["EXIT"] {
		t.Fatal("unchanged peers were rebuilt")
	}
	// Settings sessions do not depend on change in place: same object, new
	// routes in effect.
	laptop.Routes = []string{"192.168.50.0/24"}
	laptop.NAT = true
	if err := n.SetFilePeers([]config.Peer{laptop, phone}); err != nil {
		t.Fatal(err)
	}
	p := n.set.Load().byName["LAPTOP"]
	if p != after["LAPTOP"] || p.stopped() || len(p.conf().Routes) != 1 || p.natTable() == nil {
		t.Fatal("a routes/NAT change did not update the peer in place")
	}
	if got, ok := n.set.Load().routes.Lookup([4]byte{192, 168, 50, 7}); !ok || got != p {
		t.Fatal("the new route does not lead to the peer")
	}

	// A change of the handed-out IP needs new sessions: rebuilt, old one shut down.
	laptop.IP = "10.8.0.9"
	if err := n.SetFilePeers([]config.Peer{laptop, phone}); err != nil {
		t.Fatal(err)
	}
	if n.set.Load().byName["LAPTOP"] == after["LAPTOP"] || !after["LAPTOP"].stopped() {
		t.Fatal("a changed peer kept its old object")
	}
}

func TestSetFilePeersRejects(t *testing.T) {
	n, _ := testNode(t)
	exit := n.cfg.Peers[0]
	for name, peers := range map[string][]config.Peer{
		"name of an env peer":  {{Name: "EXIT", PublicKey: pub(t), IP: "10.8.0.2"}},
		"key of an env peer":   {{Name: "X", PublicKey: exit.PublicKey, IP: "10.8.0.2"}},
		"route of an env peer": {{Name: "X", PublicKey: pub(t), Routes: []string{"0.0.0.0/0"}}},
		"bad name":             {{Name: "a b", PublicKey: pub(t), IP: "10.8.0.2"}},
		"no routes":            {{Name: "X", PublicKey: pub(t)}},
	} {
		if err := n.SetFilePeers(peers); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(n.Peers()) != 1 {
		t.Fatal("a rejected change was applied")
	}
}

func TestNextFreeIP(t *testing.T) {
	n, _ := testNode(t)
	if ip, err := n.NextFreeIP(); err != nil || ip != "10.8.0.2" {
		t.Fatalf("first free = %q, %v", ip, err)
	}
	_ = n.SetFilePeers([]config.Peer{
		{Name: "A", PublicKey: pub(t), IP: "10.8.0.2"},
		{Name: "B", PublicKey: pub(t), Routes: []string{"10.8.0.3/32"}},
	})
	if ip, _ := n.NextFreeIP(); ip != "10.8.0.4" {
		t.Fatalf("next free = %q, want 10.8.0.4", ip)
	}
}

func TestInterfacePeer(t *testing.T) {
	n, _ := testNode(t)
	// The env peer EXIT routes 0.0.0.0/0; a peer with its own interface may too.
	dc := config.Peer{Name: "DC", PublicKey: pub(t), Routes: []string{"0.0.0.0/0"}, Interface: "gp-dc"}
	if err := n.SetFilePeers([]config.Peer{dc}); err != nil {
		t.Fatal(err)
	}
	set := n.set.Load()
	if p, _ := set.routes.Lookup([4]byte{1, 1, 1, 1}); p == nil || p.name != "EXIT" {
		t.Fatalf("1.1.1.1 routed to %v, want EXIT: DC is not in the route table", p)
	}
	if p := set.byName["DC"]; !p.accepts([4]byte{1, 1, 1, 1}) {
		t.Fatal("DC does not accept sources in its routes")
	}
	for _, name := range []string{"goproxy0", "lo"} {
		dc.Interface = name
		if err := n.SetFilePeers([]config.Peer{dc}); err == nil {
			t.Errorf("interface %q accepted", name)
		}
	}
	// Changing the interface replaces the peer (and with it the device).
	old := set.byName["DC"]
	dc.Interface = "gp-dc2"
	if err := n.SetFilePeers([]config.Peer{dc}); err != nil {
		t.Fatal(err)
	}
	if n.set.Load().byName["DC"] == old || !old.stopped() {
		t.Fatal("the peer was kept across an interface change")
	}
}
