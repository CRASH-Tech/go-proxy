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
		"GOPROXY_PRIVATE_KEY":        testPriv,
		"GOPROXY_LISTEN":             "0.0.0.0:443",
		"GOPROXY_TRANSPORT":          "udp",
		"GOPROXY_TUN_ADDRESS":        "10.1.254.1/24",
		"GOPROXY_PEER_DC2":           testPubA,
		"GOPROXY_PEER_DC2_ENDPOINT":  "dc2.example:443",
		"GOPROXY_PEER_DC2_ROUTES":    "10.2.0.0/16, 10.20.0.0/16",
		"GOPROXY_PEER_DC2_TRANSPORT": "tls",
		"GOPROXY_PEER_DC2_NAT":       "true",
		"GOPROXY_PEER_LAPTOP":        testPubB,
		"GOPROXY_PEER_LAPTOP_IP":     "10.1.254.10",
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
	if c.PushRoutes != "false" || c.Masquerade != "" {
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
		"GOPROXY_PRIVATE_KEY": testPriv,
		"GOPROXY_LISTEN":      "0.0.0.0:443",
		"GOPROXY_PEER_A":      testPubA,
	}
	for name, tc := range map[string]struct {
		vars map[string]string
		want string
	}{
		"no routes":      {map[string]string{}, "_ROUTES and/or _IP"},
		"ipv6 route":     {map[string]string{"GOPROXY_PEER_A_ROUTES": "fd00::/8"}, "only IPv4"},
		"bad ip":         {map[string]string{"GOPROXY_PEER_A_IP": "10.0.0.300"}, "need an IPv4 address"},
		"bad endpoint":   {map[string]string{"GOPROXY_PEER_A_ROUTES": "10.2.0.0/16", "GOPROXY_PEER_A_ENDPOINT": "dc2"}, "endpoint"},
		"nothing to do":  {map[string]string{"GOPROXY_LISTEN": "", "GOPROXY_PEER_A_ROUTES": "10.2.0.0/16"}, "nothing to do"},
		"duplicate key":  {map[string]string{"GOPROXY_PEER_A_ROUTES": "10.2.0.0/16", "GOPROXY_PEER_B": testPubA, "GOPROXY_PEER_B_ROUTES": "10.3.0.0/16"}, "same public key"},
		"shared prefix":  {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_PEER_B": testPubB, "GOPROXY_PEER_B_ROUTES": "10.8.0.2/32"}, "both peer"},
		"no peers":       {map[string]string{"GOPROXY_PEER_A": ""}, "public key"},
		"bad tun":        {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_TUN_ADDRESS": "fd00::1/64"}, "GOPROXY_TUN_ADDRESS"},
		"bad transport":  {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_TRANSPORT": "quic"}, "GOPROXY_TRANSPORT"},
		"bad push":       {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_PUSH_ROUTES": "host"}, "GOPROXY_PUSH_ROUTES"},
		"bad masquerade": {map[string]string{"GOPROXY_PEER_A_IP": "10.8.0.2", "GOPROXY_MASQUERADE": "10.0.0.0/8"}, "GOPROXY_MASQUERADE"},
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
