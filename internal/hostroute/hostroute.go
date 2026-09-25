// Package hostroute installs host routes into the node's TUN for its peers'
// prefixes (GOPROXY_PUSH_ROUTES). Two scopes:
//
// All (the way wg-quick does for AllowedIPs) -- for the host and its clients:
//
//   - a specific prefix becomes a main-table route "<prefix> dev <tun>";
//   - a default route (0.0.0.0/0) goes into its own table, used by policy rules
//     for every socket except the node's own (SO_MARK), so the connections to
//     the peers are not routed into the tunnel they carry.
//
// Clients -- only for forwarded traffic, the host's own keeps its routes:
//
//   - every prefix goes into the node's own table, and a rule sends packets that
//     did not originate on the host ("not iif lo") there.
//
// In both, the host's non-default main-table routes (connected networks)
// still win, traffic coming out of the tunnel is never sent back into it by a
// default route, and with a default route IPv6 is sent to the TUN too, where
// it is blocked instead of leaking. Only routes and rules are touched -- no sysctls
// or firewall. Everything added is removed by the returned cleanup.
package hostroute

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Scope selects whose traffic the pushed routes apply to.
type Scope int

const (
	All     Scope = iota // the host's own traffic and forwarded traffic
	Clients              // forwarded traffic only
)

// Priorities of the policy rules (ahead of the main table, 32766). They are
// cleared before use, so rules left behind by a crashed run are replaced
// rather than duplicated.
const (
	prefSuppress   = 1001 // lookup main suppress_prefixlength 0
	prefFromTunnel = 1002 // iif <tun> lookup <table> suppress_prefixlength 0
	prefFromTunEnd = 1003 // iif <tun> lookup main
	prefTunnel     = 1004 // All: not fwmark <mark> lookup <table>; Clients: not iif lo lookup <table>
)

// allPrefs lists every priority used, including those of older versions, so a
// crashed run's rules are cleared whatever version left them.
var allPrefs = []int{prefSuppress, prefFromTunnel, prefFromTunEnd, prefTunnel}

// Push routes prefixes into dev for scope. table is the routing table used for
// policy routing -- GOPROXY_FWMARK, which is also the SO_MARK of the node's own
// sockets. Problems that do not prevent the rest (an existing route, IPv6
// disabled, a strict rp_filter) are reported via warn. The returned func
// removes what was added.
func Push(scope Scope, dev string, table int, prefixes []netip.Prefix, warn func(string)) (func(), error) {
	p := &pusher{dev: dev, table: fmt.Sprint(table), warn: warn}
	var err error
	if scope == Clients {
		err = p.clients(prefixes)
	} else {
		err = p.all(prefixes)
	}
	if err != nil {
		p.cleanup()
		return nil, err
	}
	return p.cleanup, nil
}

type pusher struct {
	dev   string
	table string
	warn  func(string)
	undo  []func()
}

func (p *pusher) cleanup() {
	for i := len(p.undo) - 1; i >= 0; i-- {
		p.undo[i]()
	}
	p.undo = nil
}

// all: specific prefixes into the main table, a default via policy routing.
func (p *pusher) all(prefixes []netip.Prefix) error {
	hasDefault := false
	for _, pfx := range prefixes {
		if pfx.Bits() == 0 {
			hasDefault = true
			continue
		}
		cidr := pfx.String()
		if err := run("ip", "route", "add", cidr, "dev", p.dev); err != nil {
			if strings.Contains(err.Error(), "File exists") {
				p.warn(fmt.Sprintf("route %s already exists on the host, left unchanged", cidr))
				continue
			}
			return err
		}
		p.undo = append(p.undo, func() { _ = run("ip", "route", "del", cidr, "dev", p.dev) })
	}
	if !hasDefault {
		return nil
	}
	p.clearPolicy()
	sel := []string{"not", "fwmark", p.table}
	if err := p.policy("-4", sel, []string{"default"}); err != nil {
		return err
	}
	p.policyV6(sel)
	if strictRPFilter() {
		p.warn("rp_filter is strict and src_valid_mark is off: replies from peers will be dropped " +
			"unless you relax rp_filter or add the CONNMARK rules (README: client host setup)")
	}
	return nil
}

// clients: every prefix into the node's table, used only for forwarded packets.
func (p *pusher) clients(prefixes []netip.Prefix) error {
	p.clearPolicy()
	var dsts []string
	hasDefault := false
	for _, pfx := range prefixes {
		cidr := pfx.String()
		if pfx.Bits() == 0 {
			hasDefault = true
			cidr = "default"
		} else if out, _ := exec.Command("ip", "route", "show", "exact", cidr).Output(); len(strings.TrimSpace(string(out))) > 0 {
			p.warn(fmt.Sprintf("the host has its own route for %s, which takes precedence for clients too", cidr))
		}
		dsts = append(dsts, cidr)
	}
	sel := []string{"not", "iif", "lo"}
	if err := p.policy("-4", sel, dsts); err != nil {
		return err
	}
	if hasDefault {
		p.policyV6(sel)
	}
	// No rp_filter concern here: for forwarded packets the kernel runs the
	// reverse-path lookup with the forwarding output interface as iif, so it
	// matches "not iif lo" and finds the TUN like the forward lookup does.
	return nil
}

// clearPolicy removes rules and table routes left behind by a crashed run.
func (p *pusher) clearPolicy() {
	for _, fam := range []string{"-4", "-6"} {
		for _, pref := range allPrefs {
			for run("ip", fam, "rule", "del", "pref", fmt.Sprint(pref)) == nil {
			}
		}
		_ = run("ip", fam, "route", "flush", "table", p.table)
	}
}

// policy fills the node's table with dsts (into dev) and adds the rules:
//
//	1001  lookup main suppress_prefixlength 0          connected networks win
//	1002  iif <tun> lookup <table> suppress_prefixlength 0
//	1003  iif <tun> lookup main                        from the tunnel: transit to
//	                                                   peer prefixes, else the host's
//	                                                   routes -- never back in by default
//	1004  <sel> lookup <table>                         the rest into the TUN
//
// Without 1002/1003, a reply coming out of the tunnel to a client that the
// host reaches only via its default gateway (a LAN behind a router) would
// match the table's default route and loop back into the TUN.
func (p *pusher) policy(fam string, sel, dsts []string) error {
	p.undo = append(p.undo, func() {
		for i := len(allPrefs) - 1; i >= 0; i-- {
			_ = run("ip", fam, "rule", "del", "pref", fmt.Sprint(allPrefs[i]))
		}
		_ = run("ip", fam, "route", "flush", "table", p.table)
	})
	for _, dst := range dsts {
		if err := run("ip", fam, "route", "add", dst, "dev", p.dev, "table", p.table); err != nil {
			return err
		}
	}
	rules := [][]string{
		{"lookup", "main", "suppress_prefixlength", "0", "pref", fmt.Sprint(prefSuppress)},
		{"iif", p.dev, "lookup", p.table, "suppress_prefixlength", "0", "pref", fmt.Sprint(prefFromTunnel)},
		{"iif", p.dev, "lookup", "main", "pref", fmt.Sprint(prefFromTunEnd)},
		append(append([]string{}, sel...), "lookup", p.table, "pref", fmt.Sprint(prefTunnel)),
	}
	for _, r := range rules {
		if err := run(append([]string{"ip", fam, "rule", "add"}, r...)...); err != nil {
			return err
		}
	}
	return nil
}

// policyV6 captures IPv6 into the TUN (to be blocked) alongside a default route.
func (p *pusher) policyV6(sel []string) {
	if err := p.policy("-6", sel, []string{"default"}); err != nil {
		p.warn(fmt.Sprintf("IPv6 not captured (IPv6 disabled?): %v", err))
	}
}

// strictRPFilter reports whether strict reverse-path filtering would drop the
// replies to the node's marked connections. An interface's effective
// rp_filter is the higher of its own value and "all"; 1 is strict, 2 loose.
func strictRPFilter() bool {
	if sysctl("all/src_valid_mark") == "1" {
		return false
	}
	all := sysctl("all/rp_filter")
	paths, _ := filepath.Glob("/proc/sys/net/ipv4/conf/*/rp_filter")
	for _, path := range paths {
		iface := filepath.Base(filepath.Dir(path))
		if iface == "all" || iface == "default" {
			continue
		}
		if max(all, sysctl(iface+"/rp_filter")) == "1" {
			return true
		}
	}
	return false
}

func sysctl(name string) string {
	b, _ := os.ReadFile("/proc/sys/net/ipv4/conf/" + name)
	return strings.TrimSpace(string(b))
}

func run(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
