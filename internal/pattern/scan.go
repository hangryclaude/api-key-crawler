// Package pattern is the native engine's scanner: rules in, spans out. It reads bytes and a path and
// reports where in them a rule of the table finds a secret; it knows nothing of git, of keyguard's
// stores or of fingerprints. internal/engines adapts it to core.Engine, and that adapter is the one
// place a secret's value is read: a Finding carries spans, never the value, and nothing here prints,
// logs or errors with one.
//
// The scan of a buffer is four steps:
//
//  1. one Aho-Corasick pass finds every rule keyword (ac.go);
//  2. each hit opens or widens a window for the rules it wakes (window.go, sized by anchor.go), and a
//     rule whose keyword is only a gate runs over the whole buffer;
//  3. a rule's regex runs over its windows, the secret group is cut out of each match and the
//     rule's filter and the global one decide whether it stays (allow.go);
//  4. composite rules look for their other half, a finding that a more specific rule covers is
//     dropped, and what is left is reported with the tags the checks set (checks.go).
//
// The rules are the table in internal/pattern/rules and are held to the reference engine's
// behaviour on them; ENGINE.md says where this scanner differs and why.
package pattern

import (
	"bytes"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"time"

	"keyguard/internal/pattern/lin"
	"keyguard/internal/pattern/rules"
)

// Options configure a Scanner.
type Options struct {
	Paths   PathPolicy
	Threads int // ScanDir workers; 0 means 2
	// Regexp makes every rule run on Go's regexp, whatever its kind. It is the oracle that a test holds
	// the linear matchers to on whole scans, and the way back if a matcher is ever wrong.
	Regexp bool
}

// Finding is one secret. Offsets index the data the scan was given (plus Base, for a buffer that is
// a tile of a bigger file); the value is data[Start:End] and is the caller's to read or leave.
type Finding struct {
	Rule *rules.Rule
	Path string
	// Line is the line the whole match starts on, 1-based, the way the reference engine numbers it.
	// It is 0 for a rule about a path alone, which has no span either.
	Line       int
	Base       int // offset of the buffer in the file; 0 unless the file was read in tiles
	MatchStart int
	MatchEnd   int
	Start, End int // the secret
	Entropy    float64
	Tags       []string
}

// Secret is the value, as a view of data. It is the one way to read it.
func (f Finding) Secret(data []byte) []byte { return data[f.Start:f.End] }

// Scanner holds a rule table and everything derived from it. It is safe for concurrent use. Its
// parts are built when first needed: the prefilter on the first scan, a rule's regex on its first
// keyword hit, so that a process that scans one small buffer pays for the few rules it wakes.
type Scanner struct {
	table []rules.Rule
	opt   Options
	rt    []ruleRT
	byID  map[string]int32

	globalSpec rules.Filter
	initOnce   sync.Once
	global     *filter
	gate       *pathGate
	pre        *prefilter
	pathOnly   []int32 // rules about a path alone

	// wholeFile makes every rule run over the whole buffer when its keyword occurs, which is what the
	// reference does. Only tests set it: it is the exact answer the windows are held to.
	wholeFile bool

	// prof is the profile loop's timer, set by a test and nil in production.
	prof *ruleProf

	pool sync.Pool
}

// New makes a scanner for a table and its global filter.
func New(table []rules.Rule, global rules.Filter, o Options) *Scanner {
	s := &Scanner{table: table, opt: o, rt: make([]ruleRT, len(table)), byID: make(map[string]int32, len(table))}
	for i := range table {
		s.byID[table[i].ID] = int32(i)
	}
	s.globalSpec = global
	s.pool.New = func() any { return s.newWork() }
	return s
}

var (
	defaultOnce    sync.Once
	defaultScanner *Scanner
)

// Default is the scanner of the built-in table with keyguard's own path policy, shared by the
// process. Nothing in it is built until the first scan.
func Default() *Scanner {
	defaultOnce.Do(func() { defaultScanner = New(rules.All, rules.Global, Options{}) })
	return defaultScanner
}

// ensure builds the parts every scan needs, once.
func (s *Scanner) ensure() {
	s.initOnce.Do(func() {
		s.global = newFilter(&s.globalSpec)
		s.gate = &pathGate{policy: s.opt.Paths, global: s.global}
		s.pre = newPrefilter(s.table)
		for i := range s.table {
			if s.table[i].Re == "" && s.table[i].Path != "" {
				s.pathOnly = append(s.pathOnly, int32(i))
			}
		}
	})
}

// ruleRT is a rule made runnable.
type ruleRT struct {
	once   sync.Once
	lin    *lin.Prog // the linear matcher, for a rule of kind Shape or Assign
	reOnce sync.Once
	re     *regexp.Regexp // compiled when the rule is a Regex, or the matcher gave up
	pathRe *regexp.Regexp
	flt    *filter
	anchor anchor
	nsub   int
	needs  []needRT
}

// regex is the rule's regexp, compiled on first use. A rule that the linear matcher runs never needs
// it, unless a walk runs out of budget on hostile input.
func (rt *ruleRT) regex(r *rules.Rule) *regexp.Regexp {
	rt.reOnce.Do(func() { rt.re = regexp.MustCompile(r.Re) })
	return rt.re
}

type needRT struct {
	rule     int32
	optional bool
	win      ctxWindow
}

// init compiles the rule. It panics on a table that does not compile, which the rules package's
// tests rule out: a bad rule is a bug to find, not a condition to handle.
func (rt *ruleRT) init(s *Scanner, ri int32) {
	rt.once.Do(func() {
		r := &s.table[ri]
		if r.Re != "" {
			ast, err := syntax.Parse(r.Re, syntax.Perl)
			if err != nil {
				panic(err)
			}
			if (r.Kind == rules.Shape || r.Kind == rules.Assign) && !s.opt.Regexp {
				// The generator named the rule linear because lin.Compile took it, so this does not fail;
				// if the table was edited by hand and it does, the rule runs as a regexp.
				if p, err := lin.Build(ast); err == nil {
					rt.lin, rt.nsub = p, p.NumSubexp()
				}
			}
			if rt.lin == nil {
				rt.nsub = rt.regex(r).NumSubexp()
			}
			kws := make([]string, 0, len(r.Keywords))
			for _, k := range r.Keywords {
				if k != "" {
					kws = append(kws, strings.ToLower(k))
				}
			}
			rt.anchor = planAnchor(ast, kws)
		}
		if r.Path != "" {
			rt.pathRe = regexp.MustCompile(r.Path)
		}
		rt.flt = newFilter(&r.Filter)
		for _, n := range r.Needs {
			ci, ok := s.byID[n.ID]
			if !ok {
				panic("pattern: rule " + r.ID + " needs " + n.ID + ", which is not in the table")
			}
			rt.needs = append(rt.needs, needRT{rule: ci, optional: n.Optional, win: parseWithin(n.Within)})
		}
	})
}

// raw is a finding before the composite and specificity steps.
type raw struct {
	rule        int32
	ms, me      int // the match: its start, and its end with the trailing line breaks trimmed off
	ss, se      int // the secret
	line        int // of ms
	endLine     int // of me
	entropy     float64
	startColumn int // 1-based, as the reference counts it
	endColumn   int
}

// Window states of a rule within one buffer.
const (
	stIdle   = 0
	stOpen   = 1 // a window is open
	stGated  = 2 // a keyword was seen: the whole buffer will be searched
	stSkippd = 3 // this path is not for this rule
	stAlways = 4 // a rule with no keyword: it ran over the whole buffer
)

// work is one scan's state, pooled so a worker's arrays are reused from file to file.
type work struct {
	s *Scanner

	path     string
	gate     fileGate
	data     []byte
	baseLine int // newlines before data[0] in the file

	hits    []acHit
	state   []uint8
	wlo     []int
	whi     []int
	lastEnd []int
	touched []int32
	raws    []raw
	att     []attached
	comp    map[int32][]raw
	nl      []int32 // offsets of the newlines of the buffer, which is never bigger than a tile
	nlOK    bool
	cuts    int
	// fallbacks counts the windows the linear matcher handed back to the regexp.
	fallbacks int
	flat      []int // the matches of the window being searched
}

func (s *Scanner) newWork() *work {
	n := len(s.table)
	return &work{s: s, state: make([]uint8, n), wlo: make([]int, n), whi: make([]int, n), lastEnd: make([]int, n)}
}

func (s *Scanner) getWork() *work {
	s.ensure()
	return s.pool.Get().(*work)
}

func (s *Scanner) putWork(w *work) {
	w.data, w.path = nil, ""
	s.pool.Put(w)
}

func (w *work) reset() {
	for _, r := range w.touched {
		w.state[r], w.lastEnd[r] = stIdle, 0
	}
	w.touched = w.touched[:0]
	w.raws, w.att = w.raws[:0], w.att[:0]
	clear(w.comp)
	w.nl, w.nlOK, w.cuts, w.fallbacks = w.nl[:0], false, 0, 0
}

// lineIndex finds the newlines of the buffer, once, when the first finding needs a line number.
func (w *work) lineIndex() {
	w.nl = w.nl[:0]
	for p := 0; p < len(w.data); {
		j := bytes.IndexByte(w.data[p:], '\n')
		if j < 0 {
			break
		}
		w.nl = append(w.nl, int32(p+j))
		p += j + 1
	}
	w.nlOK = true
}

// lineOf is the 1-based line of an offset: one more than the newlines before it.
func (w *work) lineOf(off int) int {
	if !w.nlOK {
		w.lineIndex()
	}
	n, _ := slices.BinarySearch(w.nl, int32(off))
	return w.baseLine + 1 + n
}

// lineStart is the offset where a (1-based) line begins.
func (w *work) lineStart(line int) int {
	if !w.nlOK {
		w.lineIndex()
	}
	i := line - w.baseLine - 1
	if i <= 0 {
		return 0
	}
	if i > len(w.nl) {
		return len(w.data)
	}
	return int(w.nl[i-1]) + 1
}

// scanBuf finds the secrets in one buffer and returns them with offsets into it. Only findings whose
// match starts in [ownLo, ownHi) are kept, which lets a tile of a big file leave the margin it shares
// with its neighbour to that neighbour.
func (w *work) scanBuf(path string, data []byte, baseLine, ownLo, ownHi int) []Finding {
	s := w.s
	w.reset()
	w.path, w.data, w.baseLine = path, data, baseLine
	w.gate = s.gate.of(path)
	if w.gate.all || len(data) == 0 {
		return nil
	}
	m := s.pre.m

	// Step 1 and 2: the prefilter, in blocks so that a file of nothing but keywords cannot make the
	// hit list outgrow a block.
	const block = 4 << 20
	lead := max(m.maxLen-1, 0)
	for off := 0; off < len(data); off += block {
		start := max(0, off-lead)
		w.hits = m.scan(data[start:min(off+block, len(data))], w.hits[:0])
		for _, h := range w.hits {
			e := start + int(h.end)
			if e < off {
				continue // ended in the lead-in, so the previous block has it
			}
			hs, he := e-int(m.patLen[h.pat])+1, e+1
			for _, ri := range s.pre.patRules[h.pat] {
				w.hit(ri, hs, he)
			}
		}
	}
	for _, ri := range w.touched {
		switch w.state[ri] {
		case stOpen:
			w.search(ri, w.wlo[ri], w.whi[ri], &w.raws)
		case stGated:
			w.search(ri, 0, len(data), &w.raws)
		}
	}
	for _, ri := range s.pre.always {
		if w.skips(ri) {
			continue
		}
		w.state[ri] = stAlways
		w.touched = append(w.touched, ri)
		w.search(ri, 0, len(data), &w.raws)
	}

	// Step 4.
	w.composites()
	return w.report(ownLo, ownHi)
}

// pathSkips says whether rule ri is not to look at this file: the path policy, or a path pattern on the rule.
func (w *work) pathSkips(ri int32) bool {
	s := w.s
	r := &s.table[ri]
	rt := &s.rt[ri]
	rt.init(s, ri)
	return w.gate.skips(r) || (rt.pathRe != nil && !rt.pathRe.MatchString(w.path))
}

// skips says whether rule ri is not to run on its own over this file. A rule that exists to be part of
// another reports nothing by itself, and its findings must not exist beside the others: they would
// silence the rule they belong to.
func (w *work) skips(ri int32) bool {
	return w.s.table[ri].ComponentOnly || w.pathSkips(ri)
}

// hit is a keyword occurrence data[hs:he] for rule ri.
func (w *work) hit(ri int32, hs, he int) {
	switch w.state[ri] {
	case stGated, stSkippd:
		return
	case stIdle:
		w.touched = append(w.touched, ri)
		if w.skips(ri) {
			w.state[ri] = stSkippd
			return
		}
		if !w.s.rt[ri].anchor.ok || w.s.wholeFile {
			w.state[ri] = stGated
			return
		}
	}
	lo, hi, capped := windowOf(w.data, hs, he, w.s.rt[ri].anchor)
	if capped {
		w.cuts++
	}
	if w.state[ri] == stOpen {
		if lo <= w.whi[ri] && max(hi, w.whi[ri])-min(lo, w.wlo[ri]) <= mergeCap {
			w.wlo[ri], w.whi[ri] = min(lo, w.wlo[ri]), max(hi, w.whi[ri])
			return
		}
		w.search(ri, w.wlo[ri], w.whi[ri], &w.raws)
	}
	w.state[ri], w.wlo[ri], w.whi[ri] = stOpen, lo, hi
}

// find is what FindAllSubmatchIndex of the rule's regexp returns for win, flattened: stride integers
// for each match. The linear matcher answers when it can; when its walk runs out of budget, which
// takes hostile input, the regexp answers, so the result is the same either way.
func (w *work) find(rt *ruleRT, r *rules.Rule, ri int32, win []byte) (found []int, stride int) {
	if rt.lin != nil {
		stride = rt.lin.Stride()
		var t0 time.Time
		if w.s.prof != nil {
			t0 = time.Now()
		}
		var ok bool
		found, ok = rt.lin.FindAll(win, w.flat[:0])
		if w.s.prof != nil {
			w.s.prof.add(ri, &w.s.prof.lin, time.Since(t0), len(win))
		}
		if ok {
			w.flat = found[:0]
			return found, stride
		}
		w.fallbacks++
		if w.s.prof != nil {
			w.s.prof.fallbacks[ri].Add(1)
		}
	}
	stride = 2 * (rt.nsub + 1)
	var t0 time.Time
	if w.s.prof != nil {
		t0 = time.Now()
	}
	found = w.flat[:0]
	for _, m := range rt.regex(r).FindAllSubmatchIndex(win, -1) {
		found = append(found, m...)
	}
	w.flat = found[:0]
	if w.s.prof != nil {
		w.s.prof.add(ri, &w.s.prof.regex, time.Since(t0), len(win))
	}
	return found, stride
}

// search runs rule ri's regex over data[lo:hi] and appends what survives the rule's filter and the
// global one. A match that starts inside the last match taken is skipped, as it would not exist in
// a scan of the whole buffer.
func (w *work) search(ri int32, lo, hi int, out *[]raw) {
	s := w.s
	r := &s.table[ri]
	rt := &s.rt[ri]
	rt.init(s, ri)
	win := w.data[lo:hi]
	found, stride := w.find(rt, r, ri, win)
	for off := 0; off+stride <= len(found); off += stride {
		m := found[off : off+stride]
		ms, me := lo+m[0], lo+m[1]
		if ms < w.lastEnd[ri] {
			continue
		}
		w.lastEnd[ri] = me

		// The reference trims line breaks off both ends of the match before it looks for the
		// secret in it, and measures the match from its untrimmed start.
		a, b := ms, me
		for a < b && w.data[a] == '\n' {
			a++
		}
		for b > a && w.data[b-1] == '\n' {
			b--
		}
		ss, se := a, b
		if rt.nsub >= 1 {
			if g := r.Group; g > 0 {
				if g > rt.nsub {
					continue
				}
				if m[2*g] >= 0 {
					ss, se = lo+m[2*g], lo+m[2*g+1]
				} else {
					ss, se = a, a // the group did not take part: the secret is empty
				}
			} else {
				for q := 1; q <= rt.nsub; q++ {
					if m[2*q] >= 0 && m[2*q+1] > m[2*q] {
						ss, se = lo+m[2*q], lo+m[2*q+1]
						break
					}
				}
			}
		}
		secret := w.data[ss:se]
		var e float64
		if rt.flt.needsEntropy() || s.global.needsEntropy() {
			e = shannon(secret)
		}
		if rt.flt.drops(secret, e) || s.global.drops(secret, e) {
			continue
		}
		if e == 0 {
			e = shannon(secret)
		}
		// The reference measures where the match ends from the start it kept, so a match that began with a
		// line break ends a break early; the lines and columns used to place a component follow it.
		meRef := ms + (b - a)
		line, endLine := w.lineOf(ms), w.lineOf(meRef)
		ls := w.lineStart(line)
		*out = append(*out, raw{
			rule: ri, ms: ms, me: b, ss: ss, se: se, line: line, endLine: endLine, entropy: e,
			startColumn: ms - ls + 1, endColumn: meRef - w.lineStart(endLine),
		})
	}
}

// composites drops the findings of composite rules whose other parts are not near. A composite rule
// says which other rules must find something within a distance of its own finding (aws: the id and
// the secret key); those rules run over the whole buffer, which is only done for a buffer where a
// composite rule has a finding. What is found near a kept finding is attached to it, because it takes
// part in the specificity rule below: a username beside a password outranks a generic hit on its line.
func (w *work) composites() {
	s := w.s
	kept := w.raws[:0]
	for _, p := range w.raws {
		rt := &s.rt[p.rule]
		ok := true
		for _, n := range rt.needs {
			if n.optional {
				continue
			}
			found := false
			for _, c := range w.componentsNear(n, p) {
				if w.near(p, c, n.win) {
					found = true
					break
				}
			}
			if !found {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		kept = append(kept, p)
		for _, n := range rt.needs {
			for _, c := range w.componentsNear(n, p) {
				if w.near(p, c, n.win) {
					w.att = append(w.att, attached{primary: p.rule, c: c})
				}
			}
		}
	}
	w.raws = kept
}

// attached is a component finding that belongs to a finding of the composite rule primary.
type attached struct {
	primary int32
	c       raw
}

// componentsNear are the findings of the component rule of need n that can be near the finding p. When
// the need is within some lines, that is the lines around p with two to spare, so that a part is not
// searched for in a megabyte for the sake of a finding that wants it within five lines; when it is
// within no stated distance it is the whole buffer, which is cached.
func (w *work) componentsNear(n needRT, p raw) []raw {
	if !n.win.box {
		return w.componentFindings(n.rule)
	}
	if w.pathSkips(n.rule) {
		return nil
	}
	lo := w.lineStart(max(1, p.line-n.win.linesBefore-2))
	hi := len(w.data)
	if next := w.lineStart(p.endLine + n.win.linesAfter + 3); next < len(w.data) {
		hi = next - 1
	}
	var out []raw
	saved := w.lastEnd[n.rule]
	w.lastEnd[n.rule] = 0
	w.search(n.rule, max(0, lo-1), min(len(w.data), hi+1), &out)
	w.lastEnd[n.rule] = saved
	return out
}

// componentFindings are the findings of a rule that exists to be part of another, over the buffer.
func (w *work) componentFindings(ri int32) []raw {
	if got, ok := w.comp[ri]; ok {
		return got
	}
	if w.comp == nil {
		w.comp = map[int32][]raw{}
	}
	var out []raw
	if !w.pathSkips(ri) {
		saved := w.lastEnd[ri]
		w.lastEnd[ri] = 0
		w.search(ri, 0, len(w.data), &out)
		w.lastEnd[ri] = saved
	}
	w.comp[ri] = out
	return out
}

// ctxWindow is how near a component must be. It is the reference's own grammar ("5L" is five lines,
// the finding's own included; "7L,200C" adds columns; "" is anywhere in the buffer).
type ctxWindow struct {
	none                    bool
	box                     bool
	linesBefore, linesAfter int
	colsBefore, colsAfter   int
}

func parseWithin(v string) ctxWindow {
	v = strings.TrimSpace(v)
	if v == "" || v == "0" {
		return ctxWindow{none: true}
	}
	type dir struct{ before, after, both int }
	var lines, cols dir
	hasLines, hasCols := false, false
	apply := func(d *dir, marker string, n int) {
		switch marker {
		case "-":
			d.before = max(d.before, n)
		case "+":
			d.after = max(d.after, n)
		default:
			d.both = max(d.both, n)
		}
	}
	for _, tok := range strings.Split(v, ",") {
		tok = strings.TrimSpace(tok)
		marker := ""
		if tok != "" && (tok[0] == '+' || tok[0] == '-') {
			marker, tok = tok[:1], tok[1:]
		}
		unit := byte('C')
		if n := len(tok); n > 0 && (tok[n-1]|0x20 == 'c' || tok[n-1]|0x20 == 'l') {
			unit, tok = tok[n-1]&^0x20, tok[:n-1]
		}
		n := 0
		for _, c := range []byte(tok) {
			if c < '0' || c > '9' {
				panic("pattern: bad context window " + v)
			}
			n = n*10 + int(c-'0')
		}
		if unit == 'L' {
			hasLines = true
			apply(&lines, marker, max(n-1, 0))
		} else {
			hasCols = true
			apply(&cols, marker, n)
		}
	}
	w := ctxWindow{colsBefore: max(cols.before, cols.both), colsAfter: max(cols.after, cols.both)}
	switch {
	case hasLines:
		w.box = true
		w.linesBefore, w.linesAfter = max(lines.before, lines.both), max(lines.after, lines.both)
	case hasCols:
	default:
		panic("pattern: bad context window " + v)
	}
	return w
}

// near is the reference's proximity test between a composite rule's finding and a component's.
func (w *work) near(p, c raw, win ctxWindow) bool {
	if win.none {
		return true
	}
	if !win.box {
		return c.ms >= max(p.ms-win.colsBefore, 0) && c.ms < min(p.me+win.colsAfter, len(w.data))
	}
	if c.line < p.line-win.linesBefore || c.line > p.endLine+win.linesAfter {
		return false
	}
	if p.line == p.endLine && (win.colsBefore > 0 || win.colsAfter > 0) {
		col := c.startColumn - 1
		return col >= max(p.startColumn-1-win.colsBefore, 0) && col < p.endColumn+win.colsAfter
	}
	return true
}

// report applies the specificity rule, picks out what this buffer owns and turns it into Findings.
// A more specific rule's finding replaces a less specific one on the same line when its secret
// contains the other's: the generic rule that sees "password = <value>" is silent when the password
// rule has already seen it.
func (w *work) report(ownLo, ownHi int) []Finding {
	s := w.s
	slices.SortFunc(w.raws, func(a, b raw) int {
		if a.ms != b.ms {
			return a.ms - b.ms
		}
		return int(a.rule) - int(b.rule)
	})
	var byLine map[int][]attached // components attached to kept composite findings, by line; mostly none
	for _, a := range w.att {
		if byLine == nil {
			byLine = map[int][]attached{}
		}
		byLine[a.c.line] = append(byLine[a.c.line], a)
	}
	var out []Finding
	// Findings are sorted by where they start, so the ones on a line are next to each other.
	for b0 := 0; b0 < len(w.raws); {
		b1 := b0 + 1
		for b1 < len(w.raws) && w.raws[b1].line == w.raws[b0].line {
			b1++
		}
		for i := b0; i < b1; i++ {
			f := w.raws[i]
			r := &s.table[f.rule]
			if r.ComponentOnly || f.ms < ownLo || f.ms >= ownHi {
				continue
			}
			secret := w.data[f.ss:f.se]
			suppressed := false
			for j := b0; j < b1 && !suppressed; j++ {
				g := w.raws[j]
				suppressed = j != i && g.rule != f.rule && s.table[g.rule].Specificity > r.Specificity &&
					bytes.Contains(w.data[g.ss:g.se], secret)
			}
			for _, a := range byLine[f.line] {
				suppressed = suppressed || (a.primary != f.rule && a.c.rule != f.rule &&
					s.table[a.c.rule].Specificity > r.Specificity && bytes.Contains(w.data[a.c.ss:a.c.se], secret))
			}
			if suppressed {
				continue
			}
			ls := bytes.LastIndexByte(w.data[max(0, f.ss-200):f.ss], '\n') + 1 + max(0, f.ss-200)
			out = append(out, Finding{
				Rule: r, Path: w.path, Line: f.line, MatchStart: f.ms, MatchEnd: f.me,
				Start: f.ss, End: f.se, Entropy: f.entropy, Tags: tagsFor(r, secret, w.data[ls:f.ss]),
			})
		}
		b0 = b1
	}
	return out
}

// pathFindings are the findings of the rules that look at a path and nothing else.
func (w *work) pathFindings(path string) []Finding {
	s := w.s
	var out []Finding
	g := s.gate.of(path)
	if g.all {
		return nil
	}
	for _, ri := range s.pathOnly {
		r := &s.table[ri]
		rt := &s.rt[ri]
		rt.init(s, ri)
		if g.skips(r) || r.ComponentOnly || !rt.pathRe.MatchString(path) {
			continue
		}
		out = append(out, Finding{Rule: r, Path: path})
	}
	return out
}
