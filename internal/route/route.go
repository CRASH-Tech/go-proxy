// Package route is a longest-prefix-match table over IPv4 prefixes, used by a
// node to pick the peer for each packet's destination.
package route

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
)

// Table maps IPv4 prefixes to values. The zero value is empty and ready to use;
// it is not safe for concurrent writes, but concurrent Lookups are fine once it
// is built.
type Table[T any] struct {
	byLen [33]map[uint32]T
	lens  []int // prefix lengths present, longest first
}

// Insert adds prefix -> v. Inserting the same prefix twice is an error.
func (t *Table[T]) Insert(p netip.Prefix, v T) error {
	if !p.IsValid() || !p.Addr().Is4() {
		return fmt.Errorf("%s: only IPv4 prefixes are supported", p)
	}
	p = p.Masked()
	l := p.Bits()
	if t.byLen[l] == nil {
		t.byLen[l] = map[uint32]T{}
		t.lens = append(t.lens, l)
		sort.Sort(sort.Reverse(sort.IntSlice(t.lens)))
	}
	key := addrKey(p.Addr().As4())
	if _, dup := t.byLen[l][key]; dup {
		return fmt.Errorf("%s: duplicate prefix", p)
	}
	t.byLen[l][key] = v
	return nil
}

// Lookup returns the value of the longest prefix containing addr.
func (t *Table[T]) Lookup(addr [4]byte) (T, bool) {
	a := addrKey(addr)
	for _, l := range t.lens {
		if v, ok := t.byLen[l][a&mask(l)]; ok {
			return v, true
		}
	}
	var zero T
	return zero, false
}

func addrKey(a [4]byte) uint32 { return binary.BigEndian.Uint32(a[:]) }

func mask(bits int) uint32 {
	if bits == 0 {
		return 0
	}
	return ^uint32(0) << (32 - bits)
}
