package noise

import "testing"

func TestReplayFilter(t *testing.T) {
	var f replayFilter

	// In-order acceptance.
	for i := uint64(0); i < 100; i++ {
		if !f.validate(i) {
			t.Fatalf("in-order seq %d rejected", i)
		}
	}
	// Duplicates rejected.
	for i := uint64(0); i < 100; i++ {
		if f.validate(i) {
			t.Fatalf("duplicate seq %d accepted", i)
		}
	}
	// Reordering within the window is accepted once.
	var g replayFilter
	for _, s := range []uint64{5, 3, 4, 1, 2, 0} {
		if !g.validate(s) {
			t.Fatalf("reordered seq %d rejected", s)
		}
	}
	if g.validate(4) {
		t.Fatal("replay of 4 accepted")
	}

	// Large jump forward, then old packets outside window rejected.
	var h replayFilter
	h.validate(0)
	if !h.validate(10000) {
		t.Fatal("forward jump rejected")
	}
	if h.validate(10000) {
		t.Fatal("replay after jump accepted")
	}
	if h.validate(100) { // far behind 10000, outside 2048 window
		t.Fatal("stale seq accepted")
	}
	if !h.validate(10000 - 100) { // within window, not seen
		t.Fatal("in-window seq rejected")
	}
}
