package noise

import "sync"

// replayFilter is a sliding-window anti-replay filter (RFC 6479 style) for the
// per-packet counters used by the datagram (UDP) transport. It accepts each
// counter at most once and rejects counters older than the window.
const (
	replayWindowBits  = 2048
	replayBlockBits   = 64
	replayWindowWords = replayWindowBits / replayBlockBits
)

type replayFilter struct {
	mu   sync.Mutex
	last uint64
	seen bool
	ring [replayWindowWords]uint64
}

// validate reports whether seq is acceptable (new and within the window) and,
// if so, records it. It is safe for concurrent use.
func (f *replayFilter) validate(seq uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.seen {
		// First packet: accept and initialise the window on it.
		f.seen = true
		f.last = seq
		f.ring[(seq/replayBlockBits)%replayWindowWords] = 1 << (seq % replayBlockBits)
		return true
	}

	if seq > f.last {
		// Advance the window, clearing the blocks that newly enter it.
		curBlock := f.last / replayBlockBits
		newBlock := seq / replayBlockBits
		diff := newBlock - curBlock
		if diff >= replayWindowWords {
			for i := range f.ring {
				f.ring[i] = 0
			}
		} else {
			for i := uint64(1); i <= diff; i++ {
				f.ring[(curBlock+i)%replayWindowWords] = 0
			}
		}
		f.last = seq
		f.ring[(seq/replayBlockBits)%replayWindowWords] |= 1 << (seq % replayBlockBits)
		return true
	}

	// seq <= last: must be within the window and not seen before.
	if f.last-seq >= replayWindowBits {
		return false // too old
	}
	idx := (seq / replayBlockBits) % replayWindowWords
	bit := uint64(1) << (seq % replayBlockBits)
	if f.ring[idx]&bit != 0 {
		return false // replay
	}
	f.ring[idx] |= bit
	return true
}
