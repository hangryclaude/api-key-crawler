// Package lin runs a regular expression without regexp's machinery, and gets the same answer.
//
// The rules of the native engine are written as RE2 patterns. Almost all of them are plain: literals,
// character classes, runs of a class, a few alternatives and optional parts, and no repeat of a group
// without a bound. For such a pattern Go's regexp does far more than is needed (it simulates every
// path through the pattern at once, byte by byte), and it was where 80% of the scan's time went.
// This package compiles the pattern to a graph and walks it the way a backtracking matcher does:
// greedy and lazy repeats and alternatives are tried in the order Perl, and Go, say. That order is
// the definition of which match regexp reports, so the answer is the same by construction, and the
// per-rule differential fuzz in this package's tests holds it to that on 100,000 inputs per rule.
//
// What makes it fast is what the pattern lets it skip. The places a match can start are found by
// a literal prefix or by the set of bytes a match begins with, not by trying every position. A run of
// a class that nothing after it can match inside is taken whole, with no backing off (the analysis
// proves that from the sets of bytes each part can begin with). A choice or a back-off is tried only
// when the byte there is one the rest of the pattern can start with.
//
// Exactness is the contract, so there are three guards. A pattern with a part the matcher does not
// handle (a repeat of a group without a bound, a capture group inside a repeat, a pattern that can
// match the empty string) is refused by Compile, and the caller keeps regexp for it. A walk that
// spends more than its budget gives up (FindAll reports false) and the caller asks regexp, so
// hostile input costs no more than it did. And the matcher decodes UTF-8 as regexp does, a byte
// that is not valid UTF-8 being one U+FFFD, and folds case as regexp does, which includes the Kelvin
// sign and the long s.
package lin

import (
	"bytes"
	"errors"
	"regexp/syntax"
	"slices"
	"sync"
	"unicode"
	"unicode/utf8"
)

var errNullable = errors.New("lin: the pattern can match the empty string")

// Prog is a compiled pattern. It is safe for concurrent use.
type Prog struct {
	entry  *node
	ncap   int // the capture groups, not counting the whole match
	loops  int
	scan   scanner
	pool   sync.Pool
	assign bool

	custom        bool // SetBudget was called
	base, perByte int
}

// Compile parses expr the way regexp.Compile does and builds the matcher, or says why it cannot.
func Compile(expr string) (*Prog, error) {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, err
	}
	return Build(re)
}

// Build is Compile for a pattern that is already parsed with syntax.Perl.
func Build(re *syntax.Regexp) (*Prog, error) {
	b := &builder{
		any:   newClass([]rune{0, unicode.MaxRune}),
		anyNL: newClass([]rune{0, '\n' - 1, '\n' + 1, unicode.MaxRune}),
	}
	entry := b.build(re, &node{kind: kAccept})
	if b.err != nil {
		return nil, b.err
	}
	mergeRuns(entry)
	analyze(entry)
	if entry.minLen == 0 || entry.nullable {
		return nil, errNullable
	}
	if !loopsAreSafe(entry, map[*node]bool{}) {
		return nil, errors.New("lin: a repeated group can match the empty string")
	}
	p := &Prog{entry: entry, ncap: re.MaxCap(), loops: b.loops, assign: isAssign(re)}
	p.scan = planScan(entry)
	p.pool.New = func() any {
		return &machine{caps: make([]int, p.Stride()), cnt: make([]int, p.loops)}
	}
	return p, nil
}

// NumSubexp is the number of capture groups, as regexp's NumSubexp.
func (p *Prog) NumSubexp() int { return p.ncap }

// Stride is the number of integers FindAll appends for each match: the offsets of the match and of
// each group, as one entry of regexp's FindAllSubmatchIndex, with -1 for a group that took no part.
func (p *Prog) Stride() int { return 2 * (p.ncap + 1) }

// Assignment says whether the pattern has the shape of an assignment: a name, a separator and a value
// (see isAssign).
func (p *Prog) Assignment() bool { return p.assign }

// The default budget is how many steps FindAll may take over n bytes before it hands the job back:
// base + perByte*n. A step is one node of the pattern visited, so the budget is a few hundred
// microseconds a kilobyte at worst; ordinary text takes about one step a byte.
const (
	defaultBase    = 8192
	defaultPerByte = 64
)

// SetBudget changes the budget of this program to base + perByte*n steps over n bytes. A test uses it
// to make walks give up, to see that the caller's answer is the same without them. It must not be
// called while FindAll runs.
func (p *Prog) SetBudget(base, perByte int) {
	p.base, p.perByte, p.custom = base, perByte, true
}

// FindAll appends to dst what regexp's FindAllSubmatchIndex(b, -1) returns for the same pattern and
// input, flattened: Stride integers for each match. It reports false, with dst unchanged, when the
// walk used up its budget, and then the caller must ask regexp.
func (p *Prog) FindAll(b []byte, dst []int) ([]int, bool) {
	base, perByte := defaultBase, defaultPerByte
	if p.custom {
		base, perByte = p.base, p.perByte
	}
	return p.findAll(b, dst, base+perByte*len(b))
}

// Steps is how much work FindAll does over b, in the units its budget is counted in. It is for tests
// and tuning.
func (p *Prog) Steps(b []byte) int {
	const unlimited = 1 << 40
	m := p.pool.Get().(*machine)
	defer func() {
		m.b = nil
		p.pool.Put(m)
	}()
	m.b, m.fuel, m.out = b, unlimited, false
	p.walk(m, nil)
	return unlimited - m.fuel
}

func (p *Prog) findAll(b []byte, dst []int, fuel int) ([]int, bool) {
	m := p.pool.Get().(*machine)
	defer func() {
		m.b = nil // a pooled machine must not keep the buffer alive
		p.pool.Put(m)
	}()
	m.b, m.fuel, m.out = b, fuel, false
	keep := len(dst)
	dst, ok := p.walk(m, dst)
	if !ok {
		return dst[:keep], false
	}
	return dst, true
}

// walk finds the matches in m.b, one after the other, each searched for from where the last ended.
func (p *Prog) walk(m *machine, dst []int) ([]int, bool) {
	b := m.b
	from, cur := 0, 0
	for cur < len(b) {
		i := p.scan.next(b, cur)
		if i < 0 {
			break
		}
		// regexp starts a match only between runes, counting from where its search began.
		if x := b[i]; x >= 0x80 && x < 0xC0 && !boundary(b, from, i) {
			cur = i + 1
			continue
		}
		m.reset()
		if m.run(p.entry, i) {
			m.caps[0] = i
			dst = append(dst, m.caps...)
			from = m.caps[1]
			cur = from
			continue
		}
		if m.out {
			return dst, false
		}
		cur = i + 1
	}
	return dst, true
}

// boundary says whether b[i], a continuation byte, starts a rune of the input as regexp reads it
// forward from from, which is a position between runes.
func boundary(b []byte, from, i int) bool {
	j := i
	for j > from && j > i-3 && b[j] >= 0x80 && b[j] < 0xC0 {
		j--
	}
	for j < i {
		_, w := utf8.DecodeRune(b[j:])
		j += w
	}
	return j == i
}

// machine is one walk's state.
type machine struct {
	b    []byte
	caps []int
	cnt  []int
	fuel int
	out  bool
}

func (m *machine) reset() {
	for i := range m.caps {
		m.caps[i] = -1
	}
	clear(m.cnt)
}

func isWord(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func (m *machine) assert(a assertion, p int) bool {
	b := m.b
	switch a {
	case aBeginText:
		return p == 0
	case aEndText:
		return p == len(b)
	case aBeginLine:
		return p == 0 || b[p-1] == '\n'
	case aEndLine:
		return p == len(b) || b[p] == '\n'
	}
	l := p > 0 && isWord(b[p-1])
	r := p < len(b) && isWord(b[p])
	return (l != r) == (a == aWordB)
}

// can says whether the program from c could match at p, judging by the byte there alone: false means
// it certainly cannot, true means it has to be tried.
func (m *machine) can(c *node, p int) bool {
	if c.nullable {
		return true
	}
	if p < len(m.b) {
		return c.first.has(m.b[p])
	}
	return c.nullEnd
}

// run matches the program from n at position p, and reports whether it reached the end. It leaves the
// end of the match in caps[1] and the groups in caps.
func (m *machine) run(n *node, p int) bool {
	b := m.b
	for {
		if m.fuel--; m.fuel < 0 {
			m.out = true
			return false
		}
		switch n.kind {
		case kAccept:
			m.caps[1] = p
			return true
		case kFail:
			return false
		case kLit:
			l := n.lit
			if len(b)-p < len(l) || !bytes.Equal(b[p:p+len(l)], l) {
				return false
			}
			p += len(l)
			n = n.next
		case kFold:
			for i := range n.fold {
				if p >= len(b) {
					return false
				}
				fr := &n.fold[i]
				if c := b[p]; c < 0x80 {
					if !fr.ascii || (c != fr.a && c != fr.b) {
						return false
					}
					p++
				} else {
					r, w := utf8.DecodeRune(b[p:])
					if !slices.Contains(fr.other, r) {
						return false
					}
					p += w
				}
			}
			n = n.next
		case kClass:
			if p >= len(b) {
				return false
			}
			w := n.cls.at(b, p)
			if w == 0 {
				return false
			}
			p += w
			n = n.next
		case kAssert:
			if !m.assert(n.as, p) {
				return false
			}
			n = n.next
		case kSave:
			old := m.caps[n.slot]
			m.caps[n.slot] = p
			if m.run(n.next, p) {
				return true
			}
			m.caps[n.slot] = old
			return false
		case kAlt:
			for _, a := range n.alts {
				if m.can(a, p) && m.run(a, p) {
					return true
				}
			}
			return false
		case kRun:
			if n.lazy {
				return m.lazy(n, p)
			}
			q, cnt, ascii := m.extent(n, p)
			if cnt < n.min {
				return false
			}
			if n.poss || cnt == n.min {
				p, n = q, n.next
				continue
			}
			return m.backoff(n, p, q, cnt, ascii)
		case kLoop:
			saved := m.cnt[n.id]
			m.cnt[n.id] = 0
			ok := m.iterate(n, p)
			m.cnt[n.id] = saved
			return ok
		case kLoopEnd:
			return m.iterate(n.loop, p)
		}
	}
}

// extent takes the longest run of the class from p, at most max runes. It reports where it ends, how
// many runes it holds and whether they are all one byte.
func (m *machine) extent(n *node, p int) (q, cnt int, ascii bool) {
	b, c := m.b, n.cls
	q, ascii = p, true
	lim := n.max
	if lim < 0 {
		lim = len(b) - p
	}
	for cnt < lim && q < len(b) {
		x := b[q]
		if x < 0x80 {
			if !c.tab[x] {
				break
			}
			q++
		} else {
			w := c.slow(b, q)
			if w == 0 {
				break
			}
			q += w
			ascii = false
		}
		cnt++
	}
	m.fuel -= cnt >> 3
	return q, cnt, ascii
}

// backoff tries the rest of the pattern after the run holds cnt, cnt-1, ... n.min runes, longest first.
// The run began at p and ends at q.
func (m *machine) backoff(n *node, p, q, cnt int, ascii bool) bool {
	for k := cnt; ; k-- {
		if m.fuel--; m.fuel < 0 {
			m.out = true
			return false
		}
		if m.can(n.next, q) && m.run(n.next, q) {
			return true
		}
		if k == n.min {
			return false
		}
		if ascii {
			q--
		} else {
			// Walk forward again to the end of the first k-1 runes: reading backwards would have to
			// agree with reading forwards on bytes that are not UTF-8, and this cannot disagree.
			m.fuel -= k
			q = p
			for i := 0; i < k-1; i++ {
				_, w := utf8.DecodeRune(m.b[q:])
				q += w
			}
		}
	}
}

// lazy is a run that takes as few runes as the rest of the pattern lets it.
func (m *machine) lazy(n *node, p int) bool {
	b, c := m.b, n.cls
	q := p
	for i := 0; i < n.min; i++ {
		if q >= len(b) {
			return false
		}
		w := c.at(b, q)
		if w == 0 {
			return false
		}
		q += w
	}
	for cnt := n.min; ; cnt++ {
		if m.fuel--; m.fuel < 0 {
			m.out = true
			return false
		}
		if m.can(n.next, q) && m.run(n.next, q) {
			return true
		}
		if n.max >= 0 && cnt >= n.max {
			return false
		}
		if q >= len(b) {
			return false
		}
		w := c.at(b, q)
		if w == 0 {
			return false
		}
		q += w
	}
}

// iterate is the choice a repeated group offers at p after m.cnt[n.id] iterations: another one, or the rest.
func (m *machine) iterate(n *node, p int) bool {
	c := m.cnt[n.id]
	if n.lazy {
		if c >= n.min && m.can(n.next, p) && m.run(n.next, p) {
			return true
		}
		if c >= n.max {
			return false
		}
		m.cnt[n.id] = c + 1
		if m.can(n.body, p) && m.run(n.body, p) {
			return true
		}
		m.cnt[n.id] = c
		return false
	}
	if c < n.max {
		m.cnt[n.id] = c + 1
		if m.can(n.body, p) && m.run(n.body, p) {
			return true
		}
		m.cnt[n.id] = c
	}
	return c >= n.min && m.can(n.next, p) && m.run(n.next, p)
}
