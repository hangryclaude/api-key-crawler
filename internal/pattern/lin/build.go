package lin

import (
	"errors"
	"fmt"
	"regexp/syntax"
	"slices"
	"unicode"
	"unicode/utf8"
)

// The program is a graph of nodes. Each node says what it matches and where the rest of the pattern
// goes on (next), so a pattern is built from its end towards its start and a node always exists
// before the node that leads to it. That is also the order the analysis wants.

type kind uint8

const (
	kAccept  kind = iota
	kFail         // matches nothing
	kLit          // exact bytes
	kFold         // runes that match with their case folded
	kClass        // one rune of a class
	kRun          // a class repeated min to max times
	kAlt          // ordered alternatives
	kSave         // a capture boundary
	kAssert       // a zero-width assertion
	kLoop         // a bounded repeat of a group
	kLoopEnd      // the end of one iteration of a loop
)

type assertion uint8

const (
	aBeginText assertion = iota
	aEndText
	aBeginLine
	aEndLine
	aWordB
	aNoWordB
)

// foldRune is a literal rune matched without regard to case: its orbit under Unicode simple folding.
type foldRune struct {
	a, b  byte   // the ASCII members of the orbit (equal when there is one)
	ascii bool   // the orbit has an ASCII member
	other []rune // the members from 0x80 up
}

type node struct {
	kind kind
	next *node

	lit  []byte     // kLit
	fold []foldRune // kFold
	cls  *class     // kClass, kRun
	min  int        // kRun, kLoop
	max  int        // kRun, kLoop; -1 is no bound
	lazy bool       // kRun, kLoop
	poss bool       // kRun: only the longest run can lead to a match
	alts []*node    // kAlt: the entry of each branch, in priority order
	slot int        // kSave: the index in the capture array
	as   assertion  // kAssert
	body *node      // kLoop: one iteration
	loop *node      // kLoopEnd
	id   int        // kLoop: the loop's counter

	// What the analysis learns about the program from this node on.
	first    bits // the bytes it can start with
	nullable bool // it can accept without consuming anything, wherever it is
	nullEnd  bool // it can accept without consuming anything at the end of the text (true when nullable)
	minLen   int  // the fewest bytes it consumes before accepting
	done     bool
}

const (
	// maxNodes bounds the size of a program: a repeat of a group is written out once per iteration.
	maxNodes = 4000
	// maxLoop bounds the iterations of a repeated group, which are nested calls of the matcher.
	maxLoop = 300
)

var errTooBig = errors.New("lin: the pattern is too big")

type builder struct {
	loops int
	nodes int
	err   error
	any   *class
	anyNL *class
}

func (b *builder) failf(format string, a ...any) *node {
	if b.err == nil {
		b.err = fmt.Errorf("lin: "+format, a...)
	}
	return &node{kind: kFail}
}

func newFoldRune(r rune) foldRune {
	var fr foldRune
	add := func(x rune) {
		if x < 0x80 {
			if !fr.ascii {
				fr.a, fr.b, fr.ascii = byte(x), byte(x), true
			} else if byte(x) != fr.a {
				fr.b = byte(x)
			}
			return
		}
		fr.other = append(fr.other, x)
	}
	add(r)
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		add(f)
	}
	return fr
}

// plain says the rune has no other form, so the literal is the same with or without folding.
func (fr foldRune) plain() bool { return len(fr.other) == 0 && fr.a == fr.b }

// firstBytes are the bytes a rune of the orbit can start with.
func (fr foldRune) firstBytes(into *bits) {
	if fr.ascii {
		into.add(fr.a)
		into.add(fr.b)
	}
	for _, r := range fr.other {
		into.add(leadByte(r))
	}
}

// classOf is the class of a part that matches exactly one rune.
func (b *builder) classOf(re *syntax.Regexp) (*class, bool) {
	switch re.Op {
	case syntax.OpCharClass:
		return newClass(re.Rune), true
	case syntax.OpAnyCharNotNL:
		return b.anyNL, true
	case syntax.OpAnyChar:
		return b.any, true
	case syntax.OpLiteral:
		if len(re.Rune) != 1 {
			return nil, false
		}
		if re.Flags&syntax.FoldCase == 0 {
			return newClass([]rune{re.Rune[0], re.Rune[0]}), true
		}
		r := re.Rune[0]
		rs := []rune{r}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			rs = append(rs, f)
		}
		// newClass wants ascending ranges
		for i := 1; i < len(rs); i++ {
			for j := i; j > 0 && rs[j] < rs[j-1]; j-- {
				rs[j], rs[j-1] = rs[j-1], rs[j]
			}
		}
		var rr []rune
		for _, x := range rs {
			rr = append(rr, x, x)
		}
		return newClass(rr), true
	}
	return nil, false
}

func hasCapture(re *syntax.Regexp) bool {
	if re.Op == syntax.OpCapture {
		return true
	}
	for _, s := range re.Sub {
		if hasCapture(s) {
			return true
		}
	}
	return false
}

func (b *builder) build(re *syntax.Regexp, next *node) *node {
	if b.err != nil {
		return next
	}
	if b.nodes++; b.nodes > maxNodes {
		b.err = errTooBig
		return next
	}
	switch re.Op {
	case syntax.OpNoMatch:
		return &node{kind: kFail}
	case syntax.OpEmptyMatch:
		return next
	case syntax.OpLiteral:
		if slices.Contains(re.Rune, utf8.RuneError) {
			// regexp reads a byte that is not UTF-8 as this rune, so the literal matches it.
			return b.failf("a literal U+FFFD")
		}
		if re.Flags&syntax.FoldCase == 0 {
			return &node{kind: kLit, lit: []byte(string(re.Rune)), next: next}
		}
		fold := make([]foldRune, len(re.Rune))
		plain := true
		for i, r := range re.Rune {
			fold[i] = newFoldRune(r)
			plain = plain && fold[i].plain()
		}
		if plain {
			return &node{kind: kLit, lit: []byte(string(re.Rune)), next: next}
		}
		return &node{kind: kFold, fold: fold, next: next}
	case syntax.OpCharClass:
		return &node{kind: kClass, cls: newClass(re.Rune), next: next}
	case syntax.OpAnyCharNotNL:
		return &node{kind: kClass, cls: b.anyNL, next: next}
	case syntax.OpAnyChar:
		return &node{kind: kClass, cls: b.any, next: next}
	case syntax.OpBeginText:
		return &node{kind: kAssert, as: aBeginText, next: next}
	case syntax.OpEndText:
		return &node{kind: kAssert, as: aEndText, next: next}
	case syntax.OpBeginLine:
		return &node{kind: kAssert, as: aBeginLine, next: next}
	case syntax.OpEndLine:
		return &node{kind: kAssert, as: aEndLine, next: next}
	case syntax.OpWordBoundary:
		return &node{kind: kAssert, as: aWordB, next: next}
	case syntax.OpNoWordBoundary:
		return &node{kind: kAssert, as: aNoWordB, next: next}
	case syntax.OpCapture:
		closing := &node{kind: kSave, slot: 2*re.Cap + 1, next: next}
		return &node{kind: kSave, slot: 2 * re.Cap, next: b.build(re.Sub[0], closing)}
	case syntax.OpConcat:
		n := next
		for i := len(re.Sub) - 1; i >= 0; i-- {
			n = b.build(re.Sub[i], n)
		}
		return n
	case syntax.OpAlternate:
		alt := &node{kind: kAlt, next: next}
		for _, s := range re.Sub {
			alt.alts = append(alt.alts, b.build(s, next))
		}
		return alt
	case syntax.OpQuest:
		return b.repeat(re.Sub[0], 0, 1, re.Flags&syntax.NonGreedy != 0, next)
	case syntax.OpStar:
		return b.repeat(re.Sub[0], 0, -1, re.Flags&syntax.NonGreedy != 0, next)
	case syntax.OpPlus:
		return b.repeat(re.Sub[0], 1, -1, re.Flags&syntax.NonGreedy != 0, next)
	case syntax.OpRepeat:
		return b.repeat(re.Sub[0], re.Min, re.Max, re.Flags&syntax.NonGreedy != 0, next)
	}
	return b.failf("the operator %v is not supported", re.Op)
}

// repeat is sub repeated min to max times (max -1: without bound), followed by next.
func (b *builder) repeat(sub *syntax.Regexp, min, max int, lazy bool, next *node) *node {
	if max == 0 {
		return next
	}
	if cls, ok := b.classOf(sub); ok {
		return &node{kind: kRun, cls: cls, min: min, max: max, lazy: lazy, next: next}
	}
	if min == 0 && max == 1 {
		// x? is a choice between x and nothing, in the order the repeat's greediness says.
		body := b.build(sub, next)
		alt := &node{kind: kAlt, next: next, alts: []*node{body, next}}
		if lazy {
			alt.alts = []*node{next, body}
		}
		return alt
	}
	switch {
	case hasCapture(sub):
		return b.failf("a capture group inside a repeat")
	case max < 0:
		return b.failf("an unbounded repeat of a group")
	case max > maxLoop:
		return b.failf("a repeat of a group over %d times", maxLoop)
	}
	loop := &node{kind: kLoop, min: min, max: max, lazy: lazy, next: next, id: b.loops}
	b.loops++
	loop.body = b.build(sub, &node{kind: kLoopEnd, loop: loop})
	return loop
}

// sameClass says two classes hold the same runes.
func sameClass(a, b *class) bool {
	return a == b || (a.tab == b.tab && a.inval == b.inval && slices.Equal(a.ranges, b.ranges))
}

// mergeRuns joins two runs of one class that follow each other, such as x{20,1000}x{0,24}, into one,
// x{20,1024}. The two take the same text in the same order of preference: when both are greedy, the
// total is tried from the longest down, and a split of it between the two never matters, as no group
// boundary or other node sits between them; so the first total the rest of the pattern accepts is
// the same. It is what keeps the matcher from trying every split of one long run into two.
func mergeRuns(entry *node) {
	indeg := map[*node]int{}
	seen := map[*node]bool{}
	var order []*node
	var visit func(n *node)
	visit = func(n *node) {
		if n == nil || seen[n] {
			return
		}
		seen[n] = true
		order = append(order, n)
		succ := append([]*node{n.next, n.body}, n.alts...)
		for _, s := range succ {
			if s != nil {
				indeg[s]++
				visit(s)
			}
		}
	}
	visit(entry)
	for _, n := range order {
		for n.kind == kRun && n.next.kind == kRun && indeg[n.next] == 1 && n.lazy == n.next.lazy && sameClass(n.cls, n.next.cls) {
			r := n.next
			n.min += r.min
			if n.max < 0 || r.max < 0 {
				n.max = -1
			} else {
				n.max += r.max
			}
			n.next = r.next
		}
	}
}

// analyze fills in first, nullable, nullEnd and minLen of n and of everything it leads to.
func analyze(n *node) {
	if n.done {
		return
	}
	n.done = true
	switch n.kind {
	case kAccept:
		n.nullable, n.nullEnd = true, true
	case kFail:
		n.minLen = 1 << 30
	case kLoopEnd:
		// An iteration ended: what follows is another iteration or the loop's next. Claim the most,
		// which keeps every use of these facts safe and costs the pruning only inside a loop's tail.
		n.first.addRange(0, 255)
		n.nullable, n.nullEnd = true, true
	case kLit:
		analyze(n.next)
		n.first.add(n.lit[0])
		n.minLen = len(n.lit) + n.next.minLen
	case kFold:
		analyze(n.next)
		n.fold[0].firstBytes(&n.first)
		n.minLen = len(n.fold) + n.next.minLen
	case kClass:
		analyze(n.next)
		n.first = n.cls.first
		n.minLen = 1 + n.next.minLen
	case kRun:
		analyze(n.next)
		n.first = n.cls.first
		if n.min > 0 {
			n.minLen = n.min + n.next.minLen
			break
		}
		n.first.or(&n.next.first)
		n.nullable, n.nullEnd = n.next.nullable, n.next.nullEnd
		n.minLen = n.next.minLen
	case kAlt:
		n.minLen = 1 << 30
		for _, a := range n.alts {
			analyze(a)
			n.first.or(&a.first)
			n.nullable = n.nullable || a.nullable
			n.nullEnd = n.nullEnd || a.nullEnd
			n.minLen = min(n.minLen, a.minLen)
		}
	case kSave:
		analyze(n.next)
		n.first, n.nullable, n.nullEnd, n.minLen = n.next.first, n.next.nullable, n.next.nullEnd, n.next.minLen
	case kAssert:
		analyze(n.next)
		n.minLen = n.next.minLen
		if n.as == aEndText {
			// Only at the end of the text; nothing can be consumed after it.
			n.nullEnd = n.next.nullable || n.next.nullEnd
			break
		}
		n.first, n.nullable, n.nullEnd = n.next.first, n.next.nullable, n.next.nullEnd
	case kLoop:
		analyze(n.next)
		analyze(n.body)
		n.first = n.body.first
		n.minLen = n.min*n.body.minLen + n.next.minLen
		if n.min == 0 {
			n.first.or(&n.next.first)
			n.nullable, n.nullEnd = n.next.nullable, n.next.nullEnd
		}
	}
	if n.kind == kRun && !n.lazy {
		// Greedy and nothing after it can start with a byte the class holds: a shorter run would leave
		// a byte of the class where the rest needs another, so only the longest run can succeed.
		n.poss = !n.next.nullable && !n.cls.first.meets(&n.next.first)
	}
}

// loopsAreSafe says that no loop body can match the empty string, which would make the loop spin.
func loopsAreSafe(n *node, seen map[*node]bool) bool {
	if n == nil || seen[n] {
		return true
	}
	seen[n] = true
	if n.kind == kLoop && n.body.minLen == 0 {
		return false
	}
	if n.kind == kLoopEnd {
		return true
	}
	ok := loopsAreSafe(n.next, seen)
	for _, a := range n.alts {
		ok = ok && loopsAreSafe(a, seen)
	}
	return ok && loopsAreSafe(n.body, seen)
}
