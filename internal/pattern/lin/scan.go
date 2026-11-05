package lin

import "bytes"

// scanner finds the places a match can start. Trying the pattern at every byte is what regexp does and
// what costs; a match can only start where the pattern's first byte is, so the scanner skips to those.
// It has three ways of doing it, and the pattern picks the cheapest it can.
//
//   - A literal prefix (every match starts with the same bytes): bytes.Index.
//   - A pivot (every match has a given byte a bounded distance after its start, such as the colon of
//     a key made of hex groups): bytes.IndexByte for it, which runs at memory speed, then the few
//     places before it where a match could start. It wins when the pivot byte is rare in code.
//   - The set of bytes a match can begin with, tried at each byte of the input.
type scanner struct {
	prefix []byte    // when set, every match starts with these bytes (after any zero-width part)
	set    [256]bool // the bytes a match can start with
	all    bool      // every byte can start one, so there is nothing to skip

	pivoted    bool
	pv         byte // a match has this byte at start+off, for some off in [off1, off2]
	off1, off2 int
}

// A step of the plan's cost model, in nanoseconds: the cost of looking at one byte against the set, of
// one attempt of the matcher, and of one stop of the pivot search.
const (
	costScanByte = 1.0
	costAttempt  = 10.0
	costSetTest  = 3.0
	costStop     = 20.0
	costIndex    = 0.15
)

// pivot is a byte every match holds at a bounded distance from its start.
type pivot struct {
	b          byte
	off1, off2 int
	cost       float64
}

// planScan reads the scanner off the program's entry.
func planScan(entry *node) scanner {
	var s scanner
	n := entry
	for n.kind == kSave || n.kind == kAssert {
		n = n.next
	}
	if n.kind == kLit {
		s.prefix = n.lit
		return s
	}
	setP := 0.0 // the share of input bytes that are in the set
	for c := 0; c < 256; c++ {
		if s.set[c] = entry.first.has(byte(c)); s.set[c] {
			setP += freqOf(byte(c))
		}
	}
	s.all = entry.first.count() == 256
	if p, ok := bestPivot(entry, setP); ok && p.cost < costScanByte+costAttempt*setP {
		s.pivoted, s.pv, s.off1, s.off2 = true, p.b, p.off1, p.off2
	}
	return s
}

// widthOf is how many bytes the pattern takes from n up to the node stop: its fewest and its most, or
// not ok when there is no bound. Only a pattern of parts walked in order is measured (no loops).
func widthOf(n, stop *node) (lo, hi int, ok bool) {
	for n != stop {
		switch n.kind {
		case kSave, kAssert:
		case kLit:
			lo, hi = lo+len(n.lit), hi+len(n.lit)
		case kFold:
			lo += len(n.fold)
			for _, fr := range n.fold {
				hi += 1
				if len(fr.other) > 0 {
					hi += 3
				}
			}
		case kClass:
			lo, hi = lo+1, hi+n.cls.maxWidth()
		case kRun:
			if n.max < 0 {
				return 0, 0, false
			}
			lo, hi = lo+n.min, hi+n.max*n.cls.maxWidth()
		case kAlt:
			a1, a2 := 1<<30, 0
			for _, br := range n.alts {
				b1, b2, bok := widthOf(br, n.next)
				if !bok {
					return 0, 0, false
				}
				a1, a2 = min(a1, b1), max(a2, b2)
			}
			lo, hi = lo+a1, hi+a2
			n = n.next
			continue
		default:
			return 0, 0, false
		}
		n = n.next
	}
	return lo, hi, true
}

// bestPivot walks the pattern's fixed path from the start and finds the byte that is cheapest to
// search for: rare in code, and at a narrow range of distances from the start of the match.
func bestPivot(entry *node, setP float64) (best pivot, ok bool) {
	best.cost = 1e18
	lo, hi := 0, 0
	consider := func(b byte, o1, o2 int) {
		p := freqOf(b)
		cost := costIndex + p*(costStop+float64(o2-o1+1)*(costSetTest+costAttempt*setP))
		if cost < best.cost {
			best, ok = pivot{b, o1, o2, cost}, true
		}
	}
	for n := entry; n != nil && hi <= 4096; {
		switch n.kind {
		case kSave, kAssert:
			n = n.next
		case kLit:
			for i, c := range n.lit {
				consider(c, lo+i, hi+i)
			}
			lo, hi = lo+len(n.lit), hi+len(n.lit)
			n = n.next
		case kFold, kClass, kRun, kAlt:
			// step over the node: widthOf of one node, up to the node after it
			next := n.next
			w1, w2, wok := widthOf(n, next)
			if !wok {
				return
			}
			lo, hi = lo+w1, hi+w2
			n = next
		default:
			return
		}
	}
	return
}

// maxWidth is the most bytes a rune of the class takes.
func (c *class) maxWidth() int {
	if c.asciiOnly() {
		return 1
	}
	return 4
}

// next is the first position at or after i where a match can start, or -1.
func (s *scanner) next(b []byte, i int) int {
	switch {
	case len(s.prefix) == 1:
		if j := bytes.IndexByte(b[i:], s.prefix[0]); j >= 0 {
			return i + j
		}
		return -1
	case s.prefix != nil:
		if j := bytes.Index(b[i:], s.prefix); j >= 0 {
			return i + j
		}
		return -1
	case s.pivoted:
		for i+s.off1 < len(b) {
			j := bytes.IndexByte(b[i+s.off1:], s.pv)
			if j < 0 {
				return -1
			}
			q := i + s.off1 + j // where the pivot is; a match starts between q-off2 and q-off1
			for k := max(i, q-s.off2); k <= q-s.off1; k++ {
				if s.set[b[k]] {
					return k
				}
			}
			i = q - s.off1 + 1
		}
		return -1
	case s.all:
		return i
	}
	set := &s.set
	for ; i < len(b); i++ {
		if set[b[i]] {
			return i
		}
	}
	return -1
}
