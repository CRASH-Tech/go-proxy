package route

import (
	"net/netip"
	"testing"
)

func TestLongestPrefixMatch(t *testing.T) {
	var tb Table[string]
	for p, v := range map[string]string{
		"0.0.0.0/0":      "default",
		"10.0.0.0/8":     "ten",
		"10.1.0.0/16":    "ten-one",
		"203.0.113.7/32": "host",
	} {
		if err := tb.Insert(netip.MustParsePrefix(p), v); err != nil {
			t.Fatal(err)
		}
	}
	for addr, want := range map[string]string{
		"8.8.8.8":     "default",
		"10.2.3.4":    "ten",
		"10.1.200.1":  "ten-one",
		"203.0.113.7": "host",
		"203.0.113.8": "default",
	} {
		got, ok := tb.Lookup(netip.MustParseAddr(addr).As4())
		if !ok || got != want {
			t.Errorf("%s: got %q, %v; want %q", addr, got, ok, want)
		}
	}
}

func TestNoMatch(t *testing.T) {
	var tb Table[int]
	if _, ok := tb.Lookup([4]byte{1, 2, 3, 4}); ok {
		t.Fatal("empty table matched")
	}
	_ = tb.Insert(netip.MustParsePrefix("192.168.0.0/16"), 1)
	if _, ok := tb.Lookup([4]byte{192, 169, 0, 1}); ok {
		t.Fatal("matched outside the prefix")
	}
}

func TestInsertErrors(t *testing.T) {
	var tb Table[int]
	if err := tb.Insert(netip.MustParsePrefix("10.0.0.1/8"), 1); err != nil {
		t.Fatal(err)
	}
	if err := tb.Insert(netip.MustParsePrefix("10.0.0.0/8"), 2); err == nil {
		t.Fatal("duplicate (after masking) accepted")
	}
	if err := tb.Insert(netip.MustParsePrefix("2001:db8::/32"), 3); err == nil {
		t.Fatal("IPv6 prefix accepted")
	}
}
