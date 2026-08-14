// Package netsetup applies the host networking changes needed to route real
// traffic through the tunnel: IP forwarding, NAT/masquerade and routes. Every
// change made is recorded and reverted by the returned Cleanup, so the tool
// leaves the system as it found it on exit.
package netsetup

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Cleanup reverts changes made during setup, in reverse order.
type Cleanup struct {
	steps []func()
}

func (c *Cleanup) add(f func()) { c.steps = append(c.steps, f) }

// Run executes all registered revert steps (LIFO).
func (c *Cleanup) Run() {
	for i := len(c.steps) - 1; i >= 0; i-- {
		c.steps[i]()
	}
	c.steps = nil
}

func run(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnableIPForward turns on IPv4 forwarding, recording the previous value.
func EnableIPForward(c *Cleanup) error {
	const path = "/proc/sys/net/ipv4/ip_forward"
	prev, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read ip_forward: %w", err)
	}
	if strings.TrimSpace(string(prev)) == "1" {
		return nil // already on; leave it.
	}
	if err := os.WriteFile(path, []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}
	c.add(func() { _ = os.WriteFile(path, prev, 0644) })
	return nil
}

// addRule installs an iptables rule (with -A/-I) and registers its deletion.
func addRule(c *Cleanup, table string, spec ...string) error {
	add := append([]string{"iptables", "-t", table, "-A"}, spec...)
	if err := run(add...); err != nil {
		return err
	}
	del := append([]string{"iptables", "-t", table, "-D"}, spec...)
	c.add(func() { _ = run(del...) })
	return nil
}

// ServerNAT sets up masquerading so packets arriving from the tunnel subnet are
// SNAT'd to the egress interface and forwarded to the internet.
func ServerNAT(c *Cleanup, subnet, egress string) error {
	if err := EnableIPForward(c); err != nil {
		return err
	}
	if err := addRule(c, "nat", "POSTROUTING", "-s", subnet, "-o", egress, "-j", "MASQUERADE"); err != nil {
		return err
	}
	if err := addRule(c, "filter", "FORWARD", "-s", subnet, "-o", egress, "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := addRule(c, "filter", "FORWARD", "-d", subnet, "-m", "conntrack",
		"--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
		return err
	}
	return nil
}

// ClientGatewayNAT makes the client host act as a gateway: LAN traffic that is
// forwarded out of the TUN device is masqueraded to the client's tunnel IP, so
// the tunnel only ever carries a single source address (which the server can
// route back). tunDev is the TUN interface name (e.g. tun0).
func ClientGatewayNAT(c *Cleanup, tunDev string) error {
	if err := EnableIPForward(c); err != nil {
		return err
	}
	if err := addRule(c, "nat", "POSTROUTING", "-o", tunDev, "-j", "MASQUERADE"); err != nil {
		return err
	}
	if err := addRule(c, "filter", "FORWARD", "-o", tunDev, "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := addRule(c, "filter", "FORWARD", "-i", tunDev, "-j", "ACCEPT"); err != nil {
		return err
	}
	return nil
}

// DefaultRoute returns the current default gateway IP and egress interface.
func DefaultRoute() (gateway, iface string, err error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("ip route show default: %w", err)
	}
	fields := strings.Fields(string(out))
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "via":
			gateway = fields[i+1]
		case "dev":
			iface = fields[i+1]
		}
	}
	if gateway == "" || iface == "" {
		return "", "", fmt.Errorf("could not parse default route: %q", strings.TrimSpace(string(out)))
	}
	return gateway, iface, nil
}

// PinServerRoute adds a host route to serverIP via the original default gateway
// so that the encrypted tunnel connection itself is not routed back into the
// tunnel once the default route is changed.
func PinServerRoute(c *Cleanup, serverIP, gateway, iface string) error {
	if err := run("ip", "route", "add", serverIP+"/32", "via", gateway, "dev", iface); err != nil {
		// If it already exists, treat as non-fatal.
		if !strings.Contains(err.Error(), "File exists") {
			return err
		}
		return nil
	}
	c.add(func() { _ = run("ip", "route", "del", serverIP+"/32") })
	return nil
}

// AddRoutes routes each CIDR through the tunnel gateway (split tunnel). Routes
// are removed on cleanup. Existing identical routes are treated as non-fatal.
func AddRoutes(c *Cleanup, cidrs []string, tunGateway, tunDev string) error {
	for _, cidr := range cidrs {
		if err := run("ip", "route", "add", cidr, "via", tunGateway, "dev", tunDev); err != nil {
			if strings.Contains(err.Error(), "File exists") {
				continue
			}
			return err
		}
		d := cidr
		c.add(func() { _ = run("ip", "route", "del", d) })
	}
	return nil
}

// SetDefaultViaTunnel replaces the default route so all traffic goes through the
// tunnel gateway (the server's tunnel IP). The prior default is restored on
// cleanup. Uses two /1 routes so the original default entry is left intact and
// simply overridden by more-specific routes.
func SetDefaultViaTunnel(c *Cleanup, tunGateway, tunDev string) error {
	for _, dst := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("ip", "route", "add", dst, "via", tunGateway, "dev", tunDev); err != nil {
			return err
		}
		d := dst
		c.add(func() { _ = run("ip", "route", "del", d) })
	}
	return nil
}
