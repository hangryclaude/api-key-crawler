package known

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// DefaultLimit caps the matches one Match call returns. A blob holding the same key a
// million times is already a block; the cap only keeps its report from costing memory.
// Callers that care whether it was hit use MatchLimit.
const DefaultLimit = 100_000

// Matcher finds learned secrets, and the encodings of them, in content. It is immutable
// after construction and safe for concurrent use.
type Matcher struct {
	roots []*rootIndex
	n     int
}

var (
	_ core.KnownMatcher     = (*Matcher)(nil)
	_ core.VersionedMatcher = (*Matcher)(nil)
)

// rootIndex is the matching index of one store. Each root has its own salt, so each has
// its own keyring and its own hash base: a window is hashed once per root.
type rootIndex struct {
	kr      *fp.Keyring
	h       *hasher
	bits    *[1 << 18]uint64 // 2^24 bits keyed by the top bits of a window hash: the cheap reject
	first   map[uint64]int32 // exact suffix hash -> first entry that has it
	next    []int32          // the rest of that entry's chain, -1 at the end: no slice per hash
	entries []Entry
}

// NewMatcher builds a matcher from entries made with the same keyring (see EntriesFor).
// Selftest and bench use it to register planted secrets without touching disk.
func NewMatcher(kr *fp.Keyring, entries []Entry) (*Matcher, error) {
	r, err := newRootIndex(kr, entries)
	m := &Matcher{}
	if r != nil {
		m.roots = []*rootIndex{r}
		m.n = len(r.entries)
	}
	return m, err
}

// EntriesFor registers one raw value under kr: every encoded form becomes an Entry.
// Values shorter than MinLen yield nothing.
func EntriesFor(kr *fp.Keyring, name, source string, raw []byte) []Entry {
	return newEntries(kr, newHasher(kr.Base()), name, source, raw)
}

// newRootIndex indexes entries, skipping (and counting in the error) any that cannot be
// matched: a hand-edited store must not take the good entries down with it. It keeps the
// slice it is given, so callers must not modify it afterwards.
func newRootIndex(kr *fp.Keyring, entries []Entry) (*rootIndex, error) {
	r := &rootIndex{
		kr:      kr,
		h:       newHasher(kr.Base()),
		bits:    new([1 << 18]uint64),
		first:   make(map[uint64]int32, len(entries)),
		next:    make([]int32, 0, len(entries)),
		entries: entries,
	}
	bad := 0
	for i, e := range entries {
		sh, ok := parseHex64(e.SuffixHash)
		if !ok || e.Len < window || len(e.VFP) != 32 {
			if bad == 0 { // the first bad entry: from here on, build a compacted copy
				r.entries = append(make([]Entry, 0, len(entries)), entries[:i]...)
			}
			bad++
			continue
		}
		if bad > 0 {
			r.entries = append(r.entries, e)
		}
		j := int32(len(r.next))
		r.bits[sh>>46] |= 1 << (sh >> 40 & 63)
		if f, dup := r.first[sh]; dup {
			r.next = append(r.next, f)
		} else {
			r.next = append(r.next, -1)
		}
		r.first[sh] = j
	}
	if bad > 0 {
		return r, fmt.Errorf("%d malformed entries ignored", bad)
	}
	return r, nil
}

// parseHex64 reads exactly 16 lowercase hex digits, the form hex16 writes.
func parseHex64(s string) (uint64, bool) {
	if len(s) != 16 {
		return 0, false
	}
	var x uint64
	for i := 0; i < 16; i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			x = x<<4 | uint64(c-'0')
		case c >= 'a' && c <= 'f':
			x = x<<4 | uint64(c-'a'+10)
		default:
			return 0, false
		}
	}
	return x, true
}

// LoadMatcher merges the stores of every root (core.KnownRoots()). A root with no store
// contributes nothing. A root that fails to load is reported in the error but never takes
// the others down, and the returned Matcher is always usable: an environment variable may
// add a store, so a broken one must not be able to switch the real one off (PLAN.md
// invariant 4). Hooks should log the error and keep matching.
func LoadMatcher(roots []string) (*Matcher, error) {
	m := &Matcher{}
	var errs []error
	seen := make(map[string]bool)
	for _, root := range roots {
		root = filepath.Clean(root)
		if seen[root] {
			continue
		}
		seen[root] = true
		r, err := loadRoot(root)
		if err != nil {
			errs = append(errs, fmt.Errorf("known: root %s: %w", root, err))
		}
		if r != nil && len(r.entries) > 0 {
			m.roots = append(m.roots, r)
			m.n += len(r.entries)
		}
	}
	return m, errors.Join(errs...)
}

func loadRoot(root string) (*rootIndex, error) {
	dir := core.PathsAt(root).Known
	st, err := readStore(dir)
	if err != nil || st == nil {
		return nil, err
	}
	if len(st.Entries) == 0 {
		return nil, nil
	}
	// fp.Load would mint a fresh salt for a missing one, and every stored hash would then
	// silently fail to match. fp.Open never creates.
	kr, err := fp.Open(dir)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			return nil, fmt.Errorf("store has entries but its salt is unreadable: %w", err)
		}
		return nil, err
	}
	if st.SaltCheck != saltCheck(kr) {
		return nil, errors.New("store was built with a different salt; run keyguard learn")
	}
	return newRootIndex(kr, st.Entries)
}

// Len is the number of registered forms (variants included) across all roots.
func (m *Matcher) Len() int {
	if m == nil {
		return 0
	}
	return m.n
}

// Version names the learned set exactly (core.VersionedMatcher): a hash of the confirming
// fingerprint of every form in every root. The sweep rescans all of history when it changes. The
// entry count alone notices a key added but not one swapped for another (a rotated key learned
// again), and not a form added to the keys already there, which is what a new encoding is. The
// hash is of HMACs the store already holds, so it says nothing about any value.
func (m *Matcher) Version() string {
	if m == nil {
		return ""
	}
	var all []string
	for _, r := range m.roots {
		for _, e := range r.entries {
			all = append(all, e.VFP)
		}
	}
	sort.Strings(all)
	h := sha256.New()
	for _, v := range all {
		io.WriteString(h, v)
		h.Write([]byte{'\n'})
	}
	return "kv" + hex.EncodeToString(h.Sum(nil))[:16]
}

// Match returns every learned secret in data, sorted by offset. Offsets and lengths
// describe the bytes as they appear in data, so a base64 match covers the base64 text.
func (m *Matcher) Match(data []byte) []core.KnownMatch {
	out, _ := m.MatchLimit(data, DefaultLimit)
	return out
}

// MatchLimit is Match with an explicit cap. truncated reports that the data held more than
// limit matches and the scan stopped; the ones returned are then the earliest in the data.
// limit <= 0 means DefaultLimit.
func (m *Matcher) MatchLimit(data []byte, limit int) (matches []core.KnownMatch, truncated bool) {
	matches, truncated, _ = m.match(data, limit)
	return matches, truncated
}

func (m *Matcher) match(data []byte, limit int) ([]core.KnownMatch, bool, scanStats) {
	if m == nil { // a hook that failed to load a matcher and kept going still gets an answer
		return nil, false, scanStats{}
	}
	if limit <= 0 {
		limit = DefaultLimit
	}
	var all []core.KnownMatch
	var total scanStats
	truncated := false
	for _, r := range m.roots {
		ms, tr, st := r.scan(data, limit)
		all = append(all, ms...)
		truncated = truncated || tr
		total.add(st)
	}
	all = tidy(all)
	if len(all) > limit { // several roots each filled their own quota
		all, truncated = all[:limit], true
	}
	return all, truncated, total
}

// tidy sorts matches and drops the ones that say nothing new: a match inside a longer match of
// the same value (the stable part of a base64 form inside its full encoding), the other byte
// order of a UTF-16 form that overlaps one already kept, and the same bytes registered under two
// roots.
func tidy(ms []core.KnownMatch) []core.KnownMatch {
	if len(ms) < 2 {
		return ms
	}
	sort.Slice(ms, func(i, j int) bool {
		a, b := ms[i], ms[j]
		if a.Offset != b.Offset {
			return a.Offset < b.Offset
		}
		if a.Len != b.Len {
			return a.Len > b.Len
		}
		return a.FP < b.FP
	})
	out := ms[:0]
	reach := make(map[string]int)   // value fingerprint -> furthest end already seen
	reach16 := make(map[string]int) // the same, for UTF-16 matches only
	for _, c := range ms {
		end := c.Offset + c.Len
		if r, ok := reach[c.FP]; ok && r >= end {
			continue
		}
		// A UTF-16 file shows the same ASCII text to both byte orders: the big-endian form fits
		// the little-endian bytes one byte earlier, and the other way round. That is one finding.
		if utf16Label(c.Variant) && c.Offset < reach16[c.FP] {
			continue
		}
		if utf16Label(c.Variant) {
			reach16[c.FP] = end
		}
		reach[c.FP] = end
		if k := len(out) - 1; k >= 0 && out[k].Offset == c.Offset && out[k].Len == c.Len {
			continue
		}
		out = append(out, c)
	}
	return out
}

func utf16Label(v string) bool { return v == "utf16le" || v == "utf16be" }

// scanStats is what the tests use to prove the HMAC confirm, not luck, is what keeps false
// positives at zero.
type scanStats struct {
	bitHits  int // windows the bitset let through
	mapHits  int // windows whose hash is some entry's suffix hash
	checks   int // HMAC confirmations run
	confirms int // confirmations that passed
}

func (a *scanStats) add(b scanStats) {
	a.bitHits += b.bitHits
	a.mapHits += b.mapHits
	a.checks += b.checks
	a.confirms += b.confirms
}

type scanner struct {
	r     *rootIndex
	data  []byte
	out   []core.KnownMatch
	limit int
	done  bool
	st    scanStats
}

// scan rolls the window hash over data. The hash is a loop-carried multiply, which would
// cap a single chain near 4 cycles per byte, so data is cut into four independent
// segments rolled side by side and the cores' out-of-order machinery overlaps them. All
// windows are still visited: stream k owns the window ends window+k*L .. window+(k+1)*L-1,
// the first window is tested up front and the remainder after the streams.
func (r *rootIndex) scan(data []byte, limit int) ([]core.KnownMatch, bool, scanStats) {
	n := len(data)
	if n < window || len(r.entries) == 0 {
		return nil, false, scanStats{}
	}
	const minSegment = 64
	m := n - window // windows ending at window..n-1 follow the first one
	if m < 4*minSegment {
		return r.scanOrdered(data, limit)
	}
	s := scanner{r: r, data: data, limit: limit}
	bits := r.bits
	h := r.h.sum(data[:window])
	if bits[h>>46]>>(h>>40&63)&1 != 0 {
		s.candidate(window-1, h)
	}

	L := m / 4
	B := r.h.base
	tab := &r.h.out
	o0, o1, o2, o3 := data[:L], data[L:2*L], data[2*L:3*L], data[3*L:4*L]
	i0, i1, i2, i3 := data[window:window+L], data[window+L:window+2*L], data[window+2*L:window+3*L], data[window+3*L:window+4*L]
	// Equal lengths let the compiler drop the per-byte bounds checks.
	o1, o2, o3 = o1[:len(o0)], o2[:len(o0)], o3[:len(o0)]
	i0, i1, i2, i3 = i0[:len(o0)], i1[:len(o0)], i2[:len(o0)], i3[:len(o0)]
	h0 := h
	h1 := r.h.sum(data[L : L+window])
	h2 := r.h.sum(data[2*L : 2*L+window])
	h3 := r.h.sum(data[3*L : 3*L+window])
	for j := range o0 {
		h0 = h0*B + uint64(i0[j]) - tab[o0[j]]
		h1 = h1*B + uint64(i1[j]) - tab[o1[j]]
		h2 = h2*B + uint64(i2[j]) - tab[o2[j]]
		h3 = h3*B + uint64(i3[j]) - tab[o3[j]]
		if (bits[h0>>46]>>(h0>>40&63)|bits[h1>>46]>>(h1>>40&63)|
			bits[h2>>46]>>(h2>>40&63)|bits[h3>>46]>>(h3>>40&63))&1 != 0 {
			s.cold(j, L, [4]uint64{h0, h1, h2, h3})
			if s.done {
				break
			}
		}
	}
	if !s.done {
		s.roll(h3, window+4*L, n)
	}
	if s.done {
		// Four streams find matches in no particular order, so the ones kept at the limit
		// would be arbitrary. Redo it in order: this only happens on content with more
		// matches than the limit, where nobody is counting nanoseconds.
		return r.scanOrdered(data, limit)
	}
	return s.out, false, s.st
}

// scanOrdered is the single-stream scan. Its matches arrive in order, so when the limit
// bites the ones kept are the earliest in the data.
func (r *rootIndex) scanOrdered(data []byte, limit int) ([]core.KnownMatch, bool, scanStats) {
	s := scanner{r: r, data: data, limit: limit}
	h := r.h.sum(data[:window])
	if r.bits[h>>46]>>(h>>40&63)&1 != 0 {
		s.candidate(window-1, h)
	}
	s.roll(h, window, len(data))
	return s.out, s.done, s.st
}

// roll walks window ends from..to-1 one stream; h is the hash of the window ending at
// from-1.
func (s *scanner) roll(h uint64, from, to int) {
	data := s.data
	B := s.r.h.base
	tab := &s.r.h.out
	bits := s.r.bits
	for e := from; e < to && !s.done; e++ {
		h = h*B + uint64(data[e]) - tab[data[e-window]]
		if bits[h>>46]>>(h>>40&63)&1 != 0 {
			s.candidate(e, h)
		}
	}
}

// cold re-tests the four streams after the combined filter let one through.
//
//go:noinline
func (s *scanner) cold(j, L int, hs [4]uint64) {
	for k, h := range hs {
		if s.r.bits[h>>46]>>(h>>40&63)&1 != 0 {
			s.candidate(window+k*L+j, h)
			if s.done {
				return
			}
		}
	}
}

// candidate handles a window whose hash passed the bitset: look it up exactly, then
// confirm each entry sharing that suffix by HMAC over the bytes the entry would span.
//
//go:noinline
func (s *scanner) candidate(end int, h uint64) {
	if s.done {
		return
	}
	s.st.bitHits++
	f, ok := s.r.first[h]
	if !ok {
		return
	}
	s.st.mapHits++
	for ci := f; ci >= 0; ci = s.r.next[ci] {
		e := &s.r.entries[ci]
		start := end + 1 - e.Len
		if start < 0 {
			continue
		}
		s.st.checks++
		if s.r.kr.FPBytes(s.data[start:end+1]) != e.VFP {
			continue
		}
		s.st.confirms++
		if len(s.out) >= s.limit { // one more than the limit: now it is truncation
			s.done = true
			return
		}
		s.out = append(s.out, core.KnownMatch{
			EntryID: e.ID,
			Name:    e.Name,
			Source:  e.Source,
			Variant: e.Variant,
			Offset:  start,
			Len:     e.Len,
			FP:      e.FP,
			Shape:   e.Shape,
		})
	}
}
