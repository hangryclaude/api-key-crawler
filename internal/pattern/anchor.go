package pattern

import (
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A rule runs when one of its keywords occurs. Betterleaks, whose behaviour the table is held to, then
// runs the regex over the whole fragment. Running it over a window around each keyword hit is far
// cheaper and finds the same matches, provided two things hold:
//
//  1. every match of the regex contains a keyword, so a match can be located from a hit; and
//  2. the window reaches as far from the hit as a match can: in bytes, and in lines.
//
// Neither is declared in the rule data. Both are read off the regex, once, when the rule is first
// needed. A rule for which (1) cannot be shown is "gated": the keyword only wakes it, and its regex
// runs over the whole buffer, which is exactly what the reference does. That is slower and never wrong.

// span bounds how much text a regex can match: its bytes, and the newlines among them. -1 is no bound.
type span struct{ bytes, lines int }

func addN(a, b int) int {
	if a < 0 || b < 0 {
		return -1
	}
	return a + b
}

func mulN(a, n int) int {
	switch {
	case a == 0 || n == 0:
		return 0
	case a < 0 || n < 0:
		return -1
	}
	return a * n
}

func maxN(a, b int) int {
	if a < 0 || b < 0 {
		return -1
	}
	return max(a, b)
}

func (a span) add(b span) span { return span{addN(a.bytes, b.bytes), addN(a.lines, b.lines)} }
func (a span) max(b span) span { return span{maxN(a.bytes, b.bytes), maxN(a.lines, b.lines)} }
func (a span) times(n int) span {
	return span{mulN(a.bytes, n), mulN(a.lines, n)}
}

// runeLenUpTo is the longest UTF-8 form of any rune up to r.
func runeLenUpTo(r rune) int {
	switch {
	case r < 0x80:
		return 1
	case r < 0x800:
		return 2
	case r < 0x10000:
		return 3
	}
	return 4
}

// The two non-ASCII letters that (?i) folds onto ASCII ones: the Kelvin sign onto k and the long s
// onto s. A regex written (?i)[a-z] therefore matches them, and counting them would make every
// case-insensitive class up to three times as wide as the keys it is written for. They are not
// counted: a secret that holds one is not a secret, and the window would cut it short, nothing worse.
const (
	kelvinSign = 'K'
	longS      = 'ſ'
)

// foldLen is the longest UTF-8 form of r or of an ASCII-looking rune that matches it under (?i).
func foldLen(r rune) int {
	n := utf8.RuneLen(r)
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f != kelvinSign && f != longS {
			n = max(n, utf8.RuneLen(f))
		}
	}
	return n
}

// extent bounds the text one match of re can cover.
func extent(re *syntax.Regexp) span {
	switch re.Op {
	case syntax.OpLiteral:
		var s span
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				s.bytes += foldLen(r)
			} else {
				s.bytes += utf8.RuneLen(r)
			}
			if r == '\n' {
				s.lines++
			}
		}
		return s
	case syntax.OpCharClass:
		s := span{bytes: 1}
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if lo == hi && (lo == kelvinSign || lo == longS) {
				continue
			}
			s.bytes = max(s.bytes, runeLenUpTo(hi))
			if lo <= '\n' && '\n' <= hi {
				s.lines = 1
			}
		}
		return s
	case syntax.OpAnyCharNotNL:
		return span{4, 0}
	case syntax.OpAnyChar:
		return span{4, 1}
	case syntax.OpCapture:
		return extent(re.Sub[0])
	case syntax.OpQuest:
		return extent(re.Sub[0])
	case syntax.OpStar, syntax.OpPlus:
		return unbounded(extent(re.Sub[0]))
	case syntax.OpRepeat:
		s := extent(re.Sub[0])
		if re.Max < 0 {
			return unbounded(s)
		}
		return s.times(re.Max)
	case syntax.OpConcat:
		var s span
		for _, sub := range re.Sub {
			s = s.add(extent(sub))
		}
		return s
	case syntax.OpAlternate:
		var s span
		for _, sub := range re.Sub {
			s = s.max(extent(sub))
		}
		return s
	}
	return span{} // anchors, word boundaries, the empty match, no match
}

// unbounded is the extent of a part repeated without limit.
func unbounded(s span) span {
	if s.bytes == 0 && s.lines == 0 {
		return s
	}
	if s.lines == 0 {
		return span{-1, 0}
	}
	return span{-1, -1}
}

// Finite sets of strings. A part of a regex with a small, finite language is expressed as that set
// (lower case, since keywords are lower case and the prefilter ignores case); anything larger is
// "not finite" and ends a run.
const (
	setMax    = 64
	setStrMax = 40
	classMax  = 16
)

// cross is the set of concatenations, or false when it grows past the caps.
func cross(a, b []string) ([]string, bool) {
	if len(a)*len(b) > setMax {
		return nil, false
	}
	out := make([]string, 0, len(a)*len(b))
	seen := map[string]bool{}
	for _, x := range a {
		for _, y := range b {
			if len(x)+len(y) > setStrMax {
				return nil, false
			}
			if s := x + y; !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out, true
}

func union(a, b []string) ([]string, bool) {
	out := append([]string(nil), a...)
	seen := map[string]bool{}
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, len(out) <= setMax
}

// finite returns every string re can match, lower-cased, when there are few of them.
func finite(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return []string{""}, true
	case syntax.OpNoMatch:
		return nil, true
	case syntax.OpLiteral:
		s := strings.ToLower(string(re.Rune))
		return []string{s}, len(s) <= setStrMax
	case syntax.OpCharClass:
		var out []string
		seen := map[byte]bool{}
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi >= 0x80 || int(hi-lo)+1+len(out) > classMax*2 {
				return nil, false
			}
			for r := lo; r <= hi; r++ {
				c := foldByte(byte(r))
				if !seen[c] {
					seen[c] = true
					out = append(out, string(rune(c)))
				}
			}
		}
		return out, len(out) <= classMax
	case syntax.OpCapture:
		return finite(re.Sub[0])
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			f, ok := finite(sub)
			if !ok {
				return nil, false
			}
			if out, ok = union(out, f); !ok {
				return nil, false
			}
		}
		return out, true
	case syntax.OpConcat:
		out := []string{""}
		for _, sub := range re.Sub {
			f, ok := finite(sub)
			if !ok {
				return nil, false
			}
			if out, ok = cross(out, f); !ok {
				return nil, false
			}
		}
		return out, true
	case syntax.OpQuest:
		f, ok := finite(re.Sub[0])
		if !ok {
			return nil, false
		}
		return union([]string{""}, f)
	case syntax.OpRepeat:
		if re.Max < 0 || re.Max > 6 {
			return nil, false
		}
		f, ok := finite(re.Sub[0])
		if !ok {
			return nil, false
		}
		out := []string(nil)
		pow := []string{""}
		for k := 0; k <= re.Max; k++ {
			if k >= re.Min {
				if out, ok = union(out, pow); !ok {
					return nil, false
				}
			}
			if k < re.Max {
				if pow, ok = cross(pow, f); !ok {
					return nil, false
				}
			}
		}
		return out, true
	}
	return nil, false
}

// prefixes returns strings such that every match of re begins with one of them. {""} says nothing.
func prefixes(re *syntax.Regexp) []string {
	none := []string{""}
	if f, ok := finite(re); ok {
		return f
	}
	switch re.Op {
	case syntax.OpCapture:
		return prefixes(re.Sub[0])
	case syntax.OpPlus:
		return prefixes(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return prefixes(re.Sub[0])
		}
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			var ok bool
			if out, ok = union(out, prefixes(sub)); !ok {
				return none
			}
		}
		return out
	case syntax.OpConcat:
		out := []string{""}
		for _, sub := range re.Sub {
			if f, ok := finite(sub); ok {
				next, ok := cross(out, f)
				if !ok {
					return out
				}
				out = next
				continue
			}
			if next, ok := cross(out, prefixes(sub)); ok {
				return next
			}
			return out
		}
		return out
	}
	return none
}

// items flattens a regex into the parts a match is the concatenation of. Capture groups only mark
// the secret and do not change what a match covers, so they are looked through.
func items(re *syntax.Regexp, out []*syntax.Regexp) []*syntax.Regexp {
	switch re.Op {
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			out = items(sub, out)
		}
		return out
	case syntax.OpCapture:
		return items(re.Sub[0], out)
	}
	return append(out, re)
}

// anchor says how to find the matches of a rule from its keyword hits.
type anchor struct {
	// ok: every match contains a keyword hit, and before and after bound the match around it.
	ok bool
	// before bounds the text of a match that precedes the start of the hit (slack included), after
	// the text from the hit's start to the match's end.
	before, after span
}

// planAnchor reads the anchor of a regex whose rule has these (lower case) keywords.
func planAnchor(re *syntax.Regexp, keywords []string) anchor {
	if len(keywords) == 0 {
		return anchor{}
	}
	parts := items(re, nil)
	// pre[i] bounds parts[:i]; post[i] bounds parts[i:].
	pre := make([]span, len(parts)+1)
	post := make([]span, len(parts)+1)
	for i, p := range parts {
		pre[i+1] = pre[i].add(extent(p))
	}
	for i := len(parts) - 1; i >= 0; i-- {
		post[i] = post[i+1].add(extent(parts[i]))
	}

	best, bestCost := anchor{}, 1<<62
	// consider takes a set of strings that every match contains one of, starting at part start, and
	// reports whether each of them holds a keyword, which is what makes it an anchor.
	consider := func(cand []string, start int) bool {
		// slack is how far into a candidate string the keyword can sit, so how far the string can
		// start before the hit. A newline cuts the string: what follows it says nothing about the
		// text before the keyword, and a match that contains the string contains its beginning.
		slack := 0
		for _, s := range cand {
			if i := strings.IndexByte(s, '\n'); i >= 0 {
				s = s[:i]
			}
			at := keywordOffset(s, keywords)
			if at < 0 {
				return false
			}
			slack = max(slack, at)
		}
		if len(cand) == 0 {
			return false
		}
		a := anchor{ok: true, before: pre[start], after: post[start]}
		if a.before.bytes >= 0 {
			a.before.bytes += slack
		}
		if a.before == (span{-1, -1}) || a.after == (span{-1, -1}) {
			return true // no way to bound the window on that side: the whole buffer is the honest window
		}
		if c := cost(a.before) + cost(a.after); c < bestCost {
			best, bestCost = a, c
		}
		return true
	}

	cur, start := []string{""}, 0
	for i := 0; i < len(parts); {
		f, ok := finite(parts[i])
		if ok {
			if next, ok := cross(cur, f); ok {
				cur = next
				i++
				continue
			}
			consider(cur, start)
			cur, start = []string{""}, i
			continue
		}
		// The run ends at a part with no small language. What the run has may already hold a
		// keyword; if not, the first characters of this part may complete one.
		if !consider(cur, start) {
			if next, ok := cross(cur, prefixes(parts[i])); ok {
				consider(next, start)
			}
		}
		cur, start = []string{""}, i+1
		i++
	}
	consider(cur, start)
	return best
}

// keywordOffset is how far from the start of s the latest keyword occurrence begins, or -1 if no
// keyword occurs in s.
func keywordOffset(s string, keywords []string) int {
	at := -1
	for _, k := range keywords {
		at = max(at, strings.LastIndex(s, k))
	}
	return at
}

// cost orders anchors: a window that is bounded beats one that is not, and a smaller one beats a larger.
func cost(s span) int {
	const unbounded = 1 << 20
	b, l := s.bytes, s.lines
	if b < 0 {
		b = unbounded
	}
	if l < 0 {
		l = unbounded
	}
	return b + 64*l
}
