package config

import (
	"os"
	"strings"
	"testing"
)

const (
	testPriv = "4L6Q51JvHVDM5iHEMBGnEI+2/NFOHhFzCAa8RsXylF4="
	testPubA = "DTRa7Hv5ZuUQMcAcBujJ1DZ6ycnnOT39V+KxzSU/zyI="
	testPubB = "wocZkSwFrPGrAfRH0M/SHiNQ06GCRvx+jV2WJjro6z8="
)

// setEnv replaces every GOPROXY_* variable with vars for the test's duration.
func setEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "GOPROXY_") {
			t.Setenv(k, "") // restores the original value after the test
			os.Unsetenv(k)
		}
	}
	for k, v := range vars {
		t.Setenv(k, v)
	}
}

func TestLoadNodeMesh(t *testing.T) {
	setEnv(t, map[string]string{
		"GOPROXY_PRIVATE_KEY":            testPriv,
		"GOPROXY_LISTEN":                 "0.0.0.0:443",
		"GOPROXY_TRANSPORT":              "udp",
		"GOPROXY_TUN_ADDRESS":            "10.1.254.1/24",
		"GOPROXY_PEER_DC2_PUBLIC_KEY":    testPubA,
		"GOPROXY_PEER_DC2_ENDPOINT":      "dc2.example:443",
		"GOPROXY_PEER_DC2_ROUTES":        "10.2.0.0/16, 10.20.0.0/16",
		"GOPROXY_PEER_DC2_TRANSPORT":     "tls",
		"GOPROXY_PEER_DC2_NAT":           "true",
		"GOPROXY_PEER_LAPTOP_PUBLIC_KEY": testPubB,
		"GOPROXY_PEER_LAPTOP_IP":         "10.1.254.10",
	})
	c, err := LoadNode()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Peers) != 2 {
		t.Fatalf("got %d peers, want 2 (field vars must not declare peers)", len(c.Peers))
	}
	dc2, laptop := c.Peers[0], c.Peers[1]
	if dc2.Name != "DC2" || dc2.Endpoint != "dc2.example:443" || dc2.Transport != "tls" || len(dc2.Routes) != 2 || !dc2.NAT {
		t.Fatalf("DC2 = %+v", dc2)
	}
	if c.PushRoutes != "false" || c.Masquerade != "" || c.LogConns {
		t.Fatalf("PushRoutes = %q, Masquerade = %q; want both off by default", c.PushRoutes, c.Masquerade)
	}
	if laptop.Transport != "udp" || laptop.Endpoint != "" || laptop.NAT {
		t.Fatalf("LAPTOP = %+v", laptop)
	}
	pfx, err := laptop.Prefixes()
	if err != nil || len(pfx) != 1 || pfx[0].String() != "10.1.254.10/32" {
		t.Fatalf("LAPTOP prefixes = %v, %v", pfx, err)
	}
}

func TestLoadNodeErrors(t *testing.T) {
	base := map[string]string{
		"GOPROXY_PRIVATE_KEY":       testPriv,
		"GOPROXY_LISTEN":            "0.0.0.0:443",
		"GOPROXY_PEER_A_PUBLIC_KEY": testPubA,
	}
	for name, tc := range map[string]struct {
		vars map[string]string
		want string
	}{
		"no routes":      {map[string]string{}, "routes and/or an IP"},
		"ipv6 route":     {map[string]string{"GOPROXY_PEER_A_ROUTES": "fd00::/8"}, "only IPv4"},
		"bad ip":         {map[string]string{"GOPROXY_PEER_A_IP": "10.0.0.300"}, "need an IPv4 address"},
		"bad endpoint":   {map[string]string{"GOPROXY_PEER_A_ROUTES": "10.2.0.0/16", "GOPROXY_PEER_A_ENDPOINT": "dc2"}, "endpoint"},
		"nothing to do":  {map[string]string{"GOPROXY_LISTEN": "", "GOPROXY_PEER_A_ROUTES": "10.2.0.0/16"}, "nothing to do"},
		"duplicate key":  {map[string]string{"GOPROXY_PEER_A_ROUTES": "10.2.0.0/16", "GOPROXY_PEER_B_PUBLIC_KEY": testPubA, "GOPROXY_PEER_B_ROUTES": "10.3.0.0/16"}, "same public key"},
		"shared prefix":  {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_PEER_B_PUBLIC_KEY": testPubB, "GOPROXY_PEER_B_ROUTES": "10.8.0.2/32"}, "both peer"},
		"empty key":      {map[string]string{"GOPROXY_PEER_A_PUBLIC_KEY": ""}, "public key"},
		"bad tun":        {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_TUN_ADDRESS": "fd00::1/64"}, "GOPROXY_TUN_ADDRESS"},
		"bad transport":  {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_TRANSPORT": "quic"}, "GOPROXY_TRANSPORT"},
		"bad push":       {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_PUSH_ROUTES": "host"}, "GOPROXY_PUSH_ROUTES"},
		"bad masquerade": {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_MASQUERADE": "10.0.0.0/8"}, "GOPROXY_MASQUERADE"},
		"masq ips alone": {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_MASQUERADE_IPS": "10.0.0.0/8"}, "needs GOPROXY_MASQUERADE"},
		"bad masq ips":   {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_MASQUERADE": "eth0", "GOPROXY_MASQUERADE_IPS": "10.0.0.1"}, "GOPROXY_MASQUERADE_IPS"},
		"bad fwmark":     {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_FWMARK": "zero"}, "GOPROXY_FWMARK"},
		"no private key": {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_PRIVATE_KEY": ""}, "GOPROXY_PRIVATE_KEY"},
	} {
		t.Run(name, func(t *testing.T) {
			vars := map[string]string{}
			for k, v := range base {
				vars[k] = v
			}
			for k, v := range tc.vars {
				vars[k] = v
			}
			setEnv(t, vars)
			_, err := LoadNode()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestPushRoutesValues(t *testing.T) {
	for in, want := range map[string]string{"": "false", "no": "false", "TRUE": "true", "1": "true", "clients": "clients", " Clients ": "clients"} {
		if got := pushRoutes(in); got != want {
			t.Errorf("pushRoutes(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPeerNamesFromPublicKey(t *testing.T) {
	setEnv(t, map[string]string{
		"GOPROXY_PRIVATE_KEY":            testPriv,
		"GOPROXY_LISTEN":                 "0.0.0.0:443",
		"GOPROXY_PEER_DC_1_PUBLIC_KEY":   testPubA,
		"GOPROXY_PEER_DC_1_ROUTES":       "10.1.0.0/16",
		"GOPROXY_PEER_LAPTOP_PUBLIC_KEY": testPubB,
		"GOPROXY_PEER_LAPTOP_IP":         "10.8.0.2",
		"GOPROXY_PEER_LAPTOP_INSECURE":   "false",
		"GOPROXY_TLS_INSECURE":           "true",
		"GOPROXY_PEER_OLDSTYLE":          testPubB, // not a declaration any more
	})
	c, err := LoadNode()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Peers) != 2 || c.Peers[0].Name != "DC_1" || c.Peers[1].Name != "LAPTOP" {
		t.Fatalf("peers = %+v", c.Peers)
	}
	if !c.Peers[0].TLS.Insecure || c.Peers[1].TLS.Insecure {
		t.Fatal("GOPROXY_TLS_INSECURE must be the default and _INSECURE=false must override it")
	}
	if c.Peers[0].Transport != "aead" || c.Peers[0].KeepaliveSec != 25 {
		t.Fatalf("defaults not applied: %+v", c.Peers[0])
	}
}

func TestDataDirAndWeb(t *testing.T) {
	// A key kept in the data dir, no peers yet, managed in the web UI.
	setEnv(t, map[string]string{
		"GOPROXY_DATA_DIR":     "/var/lib/goproxy",
		"GOPROXY_WEB_LISTEN":   "127.0.0.1:8080",
		"GOPROXY_WEB_PASSWORD": "secret",
	})
	if _, err := LoadNode(); err != nil {
		t.Fatalf("a web-managed node with no peers and no key yet: %v", err)
	}

	setEnv(t, map[string]string{"GOPROXY_DATA_DIR": "/d", "GOPROXY_WEB_LISTEN": "127.0.0.1:8080"})
	if _, err := LoadNode(); err == nil || !strings.Contains(err.Error(), "GOPROXY_WEB_PASSWORD") {
		t.Fatalf("web UI without a password: %v", err)
	}
	setEnv(t, map[string]string{"GOPROXY_WEB_LISTEN": "127.0.0.1:8080", "GOPROXY_WEB_PASSWORD": "x"})
	if _, err := LoadNode(); err == nil || !strings.Contains(err.Error(), "GOPROXY_PRIVATE_KEY") {
		t.Fatalf("no key and no data dir: %v", err)
	}
}

func TestValidatePeers(t *testing.T) {
	a := Peer{Name: "A", PublicKey: testPubA, Routes: []string{"10.1.0.0/16"}}
	b := Peer{Name: "A", PublicKey: testPubB, IP: "10.8.0.2"}
	if err := ValidatePeers([]Peer{a, b}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("duplicate name: %v", err)
	}
	b.Name = "bad name"
	if err := ValidatePeers([]Peer{a, b}); err == nil {
		t.Fatal("a name with a space was accepted")
	}
	b.Name = "B"
	if err := ValidatePeers([]Peer{a, b}); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsOverlay(t *testing.T) {
	dir := t.TempDir()
	setEnv(t, map[string]string{
		"GOPROXY_DATA_DIR":          dir,
		"GOPROXY_WEB_LISTEN":        "127.0.0.1:8080",
		"GOPROXY_WEB_PASSWORD":      "x",
		"GOPROXY_TUN_ADDRESS":       "10.171.254.1/24", // the environment wins
		"GOPROXY_PEER_A_PUBLIC_KEY": testPubA,
		"GOPROXY_PEER_A_ROUTES":     "10.4.0.0/16",
	})
	if err := WriteSettings(dir, map[string]string{
		"GOPROXY_LISTEN":          "0.0.0.0:443",
		"GOPROXY_TRANSPORT":       "udp",
		"GOPROXY_TUN_ADDRESS":     "10.9.0.1/24",
		"GOPROXY_PSK":             "from-ui",
		"GOPROXY_WEB_PASSWORD":    "ignored: not editable",
		"GOPROXY_LOG_CONNECTIONS": "true",
	}); err != nil {
		t.Fatal(err)
	}
	c, err := LoadNode()
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "0.0.0.0:443" || c.Transport != "udp" || !c.LogConns {
		t.Fatalf("settings not applied: listen %q transport %q log %v", c.Listen, c.Transport, c.LogConns)
	}
	if c.Address != "10.171.254.1/24" || c.WebPassword != "x" {
		t.Fatalf("the environment must win: tun %q", c.Address)
	}
	if c.Peers[0].PSK != "from-ui" || c.Peers[0].Transport != "udp" {
		t.Fatalf("peer defaults must follow the settings: %+v", c.Peers[0])
	}
	want := map[string]string{"GOPROXY_TUN_ADDRESS": "env", "GOPROXY_LISTEN": "settings", "GOPROXY_MASQUERADE": "default"}
	for k, v := range want {
		if c.Sources[k] != v {
			t.Errorf("source of %s = %q, want %q", k, c.Sources[k], v)
		}
	}
	if _, err := LoadNodeWith(map[string]string{"GOPROXY_TRANSPORT": "quic"}); err == nil {
		t.Fatal("invalid settings accepted")
	}
	m, _ := ReadSettings(dir)
	if _, ok := m["GOPROXY_WEB_PASSWORD"]; ok {
		t.Fatal("a setting that is not editable was saved")
	}
}

func TestDisabledPeerSharesRoutes(t *testing.T) {
	a := Peer{Name: "DC1", PublicKey: testPubA, Routes: []string{"10.0.0.0/8"}}
	b := Peer{Name: "DC2", PublicKey: testPubB, Routes: []string{"10.0.0.0/8"}, Disabled: true}
	if err := ValidatePeers([]Peer{a, b}); err != nil {
		t.Fatalf("a disabled standby with the same routes: %v", err)
	}
	b.Disabled = false
	if err := ValidatePeers([]Peer{a, b}); err == nil {
		t.Fatal("two enabled peers with the same route accepted")
	}
}

func TestWebPath(t *testing.T) {
	for in, want := range map[string]string{"": "", "/": "", "k7Qm": "/k7Qm", "/a/b/": "/a/b", " x ": "/x"} {
		if got := webPath(in); got != want {
			t.Errorf("webPath(%q) = %q, want %q", in, got, want)
		}
	}
}
