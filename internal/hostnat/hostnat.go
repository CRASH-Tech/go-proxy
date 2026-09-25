// Package hostnat masquerades source networks out of a host interface
// (GOPROXY_MASQUERADE, GOPROXY_MASQUERADE_IPS): by default the node's TUN
// network, so clients whose traffic leaves the tunnel here -- road warriors,
// other nodes' clients -- reach the internet with the host's address; or e.g.
// a LAN whose router sends everything to the node, so traffic the node sends
// straight back out of the same interface does not loop. It installs iptables
// rules and removes them again; sysctls stay the admin's.
package hostnat

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Masquerade adds, for traffic from each of networks out of iface:
//
//	-t nat    POSTROUTING -s <network> -o <iface> -j MASQUERADE
//	-t filter FORWARD     -s <network> -o <iface> -j ACCEPT
//	-t filter FORWARD     -d <network> -i <iface> -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
//
// The FORWARD rules matter where the policy is DROP (e.g. hosts running
// docker). Identical rules left behind by a crashed run are replaced rather
// than duplicated. Problems that do not prevent it (forwarding off) are
// reported via warn. The returned func removes the rules.
func Masquerade(networks []string, iface string, warn func(string)) (func(), error) {
	var rules [][]string
	for _, network := range networks {
		rules = append(rules,
			[]string{"-t", "nat", "POSTROUTING", "-s", network, "-o", iface, "-j", "MASQUERADE"},
			[]string{"-t", "filter", "FORWARD", "-s", network, "-o", iface, "-j", "ACCEPT"},
			[]string{"-t", "filter", "FORWARD", "-d", network, "-i", iface,
				"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"})
	}
	var added [][]string
	cleanup := func() {
		for i := len(added) - 1; i >= 0; i-- {
			_ = iptables("-D", added[i])
		}
	}
	for _, r := range rules {
		for iptables("-D", r) == nil {
		}
		if err := iptables("-A", r); err != nil {
			cleanup()
			return nil, err
		}
		added = append(added, r)
	}
	if _, err := os.Stat("/sys/class/net/" + iface); err != nil {
		warn(fmt.Sprintf("interface %s does not exist (yet): the rules apply once it appears", iface))
	}
	if b, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); strings.TrimSpace(string(b)) != "1" {
		warn("net.ipv4.ip_forward is off: nothing will be forwarded until it is enabled")
	}
	return cleanup, nil
}

// iptables runs "iptables -t <table> <op> <chain> <spec...>" for a rule given
// as table, chain and spec.
func iptables(op string, rule []string) error {
	args := append([]string{rule[0], rule[1], op}, rule[2:]...)
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
