package pattern

import (
	"slices"
	"strings"

	"keyguard/internal/pattern/rules"
)

// The prefilter is one Aho-Corasick automaton over every rule's keywords, compiled to a dense DFA so
// that a byte costs one table load. Three things keep that load cheap:
//
//   - byte classes: only bytes that occur in a keyword get a class of their own, and ASCII
//     upper case shares the class of lower case, so case folding costs nothing per byte;
//   - states that report a keyword are numbered last, so "did anything match" is one comparison;
//   - four lanes: the walk is a chain of dependent loads, so four independent stretches of the
//     buffer advance in step and the core overlaps their latencies.
//
// It reports where a keyword ends and which keyword it was. What a rule does with that is
// window.go's business.

// acHit is one keyword occurrence: pat is the index in the automaton's pattern list and end the
// offset of its last byte.
type acHit struct {
	end int32
	pat int32
}

type automaton struct {
	cls      [256]uint8
	next     []uint32 // premultiplied: an entry is target state << shift, so no multiply per byte
	shift    uint32
	outBase  uint32 // a state at or above it has at least one keyword ending there
	outStart []int32
	outPats  []int32
	patLen   []int32
	maxLen   int
}

// buildAutomaton compiles lower-case ASCII patterns. Patterns may share bytes and prefixes; an
// empty pattern is the caller's mistake and is skipped.
func buildAutomaton(pats []string) *automaton {
	a := &automaton{patLen: make([]int32, len(pats))}

	// Byte classes. Class 0 is every byte no keyword uses, so most of the input steps through
	// the root and stays there.
	var used [256]bool
	for _, p := range pats {
		for i := 0; i < len(p); i++ {
			used[foldByte(p[i])] = true
		}
		a.maxLen = max(a.maxLen, len(p))
	}
	var id [256]uint8
	nc := 1
	for b := 0; b < 256; b++ {
		if used[b] {
			id[b] = uint8(nc)
			nc++
		}
	}
	for b := 0; b < 256; b++ {
		a.cls[b] = id[foldByte(byte(b))]
	}
	for 1<<a.shift < nc {
		a.shift++
	}

	// The trie, with the root as state 0. goTo is row-major: state * nc + class.
	goTo := make([]int32, nc)
	for i := range goTo {
		goTo[i] = -1
	}
	own := [][]int32{nil} // patterns that end exactly at a state
	for pi, p := range pats {
		a.patLen[pi] = int32(len(p))
		if p == "" {
			continue
		}
		s := int32(0)
		for i := 0; i < len(p); i++ {
			c := int(a.cls[p[i]])
			if goTo[int(s)*nc+c] < 0 {
				goTo[int(s)*nc+c] = int32(len(own))
				own = append(own, nil)
				for q := 0; q < nc; q++ {
					goTo = append(goTo, -1)
				}
			}
			s = goTo[int(s)*nc+c]
		}
		own[s] = append(own[s], int32(pi))
	}
	n := len(own)

	// Failure links by breadth first search; a missing edge is filled with the failure state's
	// edge, which turns the automaton into a DFA. A state also reports what its failure state does.
	fail := make([]int32, n)
	outs := make([][]int32, n)
	copy(outs, own)
	queue := make([]int32, 0, n)
	for c := 0; c < nc; c++ {
		if v := goTo[c]; v < 0 {
			goTo[c] = 0
		} else {
			queue = append(queue, v)
		}
	}
	for qi := 0; qi < len(queue); qi++ {
		u := queue[qi]
		for c := 0; c < nc; c++ {
			v := goTo[int(u)*nc+c]
			f := goTo[int(fail[u])*nc+c]
			if v < 0 {
				goTo[int(u)*nc+c] = f
				continue
			}
			fail[v] = f
			if len(outs[f]) > 0 {
				outs[v] = append(slices.Clone(outs[v]), outs[f]...)
			}
			queue = append(queue, v)
		}
	}

	// Renumber: quiet states first (the root stays 0), reporting states last.
	renum := make([]int32, n)
	quiet := 0
	for s := 0; s < n; s++ {
		if len(outs[s]) == 0 {
			renum[s] = int32(quiet)
			quiet++
		}
	}
	k := quiet
	order := make([]int32, 0, n-quiet)
	for s := 0; s < n; s++ {
		if len(outs[s]) > 0 {
			renum[s] = int32(k)
			k++
			order = append(order, int32(s))
		}
	}
	a.outBase = uint32(quiet) << a.shift
	a.next = make([]uint32, n<<a.shift)
	for s := 0; s < n; s++ {
		base := int(renum[s]) << a.shift
		for c := 0; c < nc; c++ {
			a.next[base+c] = uint32(renum[goTo[s*nc+c]]) << a.shift
		}
	}
	for _, s := range order {
		a.outStart = append(a.outStart, int32(len(a.outPats)))
		a.outPats = append(a.outPats, outs[s]...)
	}
	a.outStart = append(a.outStart, int32(len(a.outPats)))
	return a
}

func foldByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func (a *automaton) emit(hits []acHit, s uint32, pos int) []acHit {
	k := (s - a.outBase) >> a.shift
	for _, p := range a.outPats[a.outStart[k]:a.outStart[k+1]] {
		hits = append(hits, acHit{int32(pos), p})
	}
	return hits
}

// scan1 walks buf[lo:hi] on one lane and appends the keywords that end there. The state starts at
// the root, so a keyword that began before lo is not seen; scan4 feeds lead-in for that.
func (a *automaton) scan1(buf []byte, lo, hi int, hits []acHit) []acHit {
	next, cls, out := a.next, &a.cls, a.outBase
	var s uint32
	for i := lo; i < hi; i++ {
		s = next[s+uint32(cls[buf[i]])]
		if s >= out {
			hits = a.emit(hits, s, i)
		}
	}
	return hits
}

// lanesMin is the smallest buffer worth four lanes: below it the lead-in costs more than it saves.
const lanesMin = 4096

// scan appends every keyword occurrence in buf, in the order its last byte appears.
func (a *automaton) scan(buf []byte, hits []acHit) []acHit {
	return a.scanLanes(buf, hits, 4)
}

// scanLanes is scan with a choice of lanes (1 or 4), so that a test can hold them equal.
func (a *automaton) scanLanes(buf []byte, hits []acHit, lanes int) []acHit {
	L := len(buf)
	if lanes < 4 || L < lanesMin || a.maxLen == 0 {
		return a.scan1(buf, 0, L, hits)
	}
	// Lane j owns the end positions [j*n, (j+1)*n). Its walk starts maxLen-1 bytes earlier, which
	// is enough to put the automaton in the state the one-lane walk would be in at j*n, and the
	// hits it finds in that lead-in are dropped. Each lane takes the same number of steps, so the
	// last lane's start is pulled back to leave room for them.
	ov := a.maxLen - 1
	n := (L + 3) / 4
	F := n + ov
	if F > L {
		return a.scan1(buf, 0, L, hits)
	}
	var st [4]int
	for j := range st {
		st[j] = min(max(j*n-ov, 0), L-F)
	}
	b0, b1, b2, b3 := buf[st[0]:st[0]+F], buf[st[1]:st[1]+F], buf[st[2]:st[2]+F], buf[st[3]:st[3]+F]
	b1, b2, b3 = b1[:len(b0)], b2[:len(b0)], b3[:len(b0)] // lets the compiler drop the bounds checks
	next, cls, out := a.next, &a.cls, a.outBase
	var s0, s1, s2, s3 uint32
	var lane [4][]acHit
	for t := range b0 {
		s0 = next[s0+uint32(cls[b0[t]])]
		s1 = next[s1+uint32(cls[b1[t]])]
		s2 = next[s2+uint32(cls[b2[t]])]
		s3 = next[s3+uint32(cls[b3[t]])]
		if s0 >= out {
			lane[0] = a.emit(lane[0], s0, st[0]+t)
		}
		if s1 >= out {
			lane[1] = a.emit(lane[1], s1, st[1]+t)
		}
		if s2 >= out {
			lane[2] = a.emit(lane[2], s2, st[2]+t)
		}
		if s3 >= out {
			lane[3] = a.emit(lane[3], s3, st[3]+t)
		}
	}
	// The lanes own consecutive stretches, so appending them in order keeps the hits sorted by end.
	for j := range lane {
		lo, hi := j*n, min((j+1)*n, L)
		for _, h := range lane[j] {
			if int(h.end) >= lo && int(h.end) < hi {
				hits = append(hits, h)
			}
		}
	}
	return hits
}

// prefilter ties the automaton to the rule table: which rules a keyword wakes, and which rules have
// no keyword and so are always awake.
type prefilter struct {
	m        *automaton
	pats     []string
	patRules [][]int32 // per pattern, the rules that list it
	always   []int32   // rules with no keyword
}

func newPrefilter(table []rules.Rule) *prefilter {
	p := &prefilter{}
	index := map[string]int{}
	for ri := range table {
		r := &table[ri]
		kept := 0
		for _, k := range r.Keywords {
			k = strings.ToLower(k)
			if k == "" {
				continue
			}
			kept++
			pi, ok := index[k]
			if !ok {
				pi = len(p.pats)
				index[k] = pi
				p.pats = append(p.pats, k)
				p.patRules = append(p.patRules, nil)
			}
			if rs := p.patRules[pi]; len(rs) == 0 || rs[len(rs)-1] != int32(ri) {
				p.patRules[pi] = append(rs, int32(ri))
			}
		}
		if kept == 0 && r.Re != "" {
			p.always = append(p.always, int32(ri))
		}
	}
	p.m = buildAutomaton(p.pats)
	return p
}
