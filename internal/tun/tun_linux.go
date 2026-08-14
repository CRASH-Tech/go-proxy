// Package tun creates and configures a Linux TUN (layer-3) device and exposes
// it as a packet-oriented reader/writer. Each Read returns exactly one IP
// packet and each Write must contain exactly one IP packet (IFF_NO_PI).
package tun

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	cIFFTUN   = 0x0001
	cIFFNOPI  = 0x1000
	cTUNSETIF = 0x400454ca
)

// ifreq mirrors struct ifreq for the TUNSETIFF ioctl. Total size 40 bytes.
type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// Device is an open TUN interface.
type Device struct {
	f    *os.File
	name string

	writeMu sync.Mutex
}

// Open creates (or attaches to) a TUN device. If name is empty the kernel
// assigns one (e.g. tun0). The chosen name is available via Name().
func Open(name string) (*Device, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w (need root and the tun module)", err)
	}

	var req ifreq
	copy(req.name[:], name)
	req.flags = cIFFTUN | cIFFNOPI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(cTUNSETIF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}

	realName := string(req.name[:])
	if i := strings.IndexByte(realName, 0); i >= 0 {
		realName = realName[:i]
	}

	return &Device{f: f, name: realName}, nil
}

// Name returns the interface name (e.g. "tun0").
func (d *Device) Name() string { return d.name }

// Read reads one IP packet into buf and returns its length.
func (d *Device) Read(buf []byte) (int, error) { return d.f.Read(buf) }

// Write writes one IP packet.
func (d *Device) Write(pkt []byte) (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.f.Write(pkt)
}

// Close closes the device.
func (d *Device) Close() error { return d.f.Close() }

// Configure brings the interface up with the given CIDR address and MTU using
// the iproute2 tools.
func (d *Device) Configure(cidr string, mtu int) error {
	steps := [][]string{
		{"ip", "link", "set", "dev", d.name, "up"},
		{"ip", "link", "set", "dev", d.name, "mtu", fmt.Sprintf("%d", mtu)},
		{"ip", "addr", "add", cidr, "dev", d.name},
	}
	for _, s := range steps {
		if out, err := exec.Command(s[0], s[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(s, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}
