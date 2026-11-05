package lin_test

import (
	"math/rand/v2"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The sampler writes inputs for a pattern by walking its syntax tree, so the test holds no
// secret-shaped literal: whatever a rule looks for, the sampler reads it out of the rule at run time.
// It makes inputs that match, inputs that nearly match (a mutation of one that matches), and noise
// built from the pattern's own words.

type sampler struct {
	r     *rand.Rand
	words []string // the literals of the pattern, which make noise that is near the pattern
}

func newSampler(seed uint64, re *syntax.Regexp) *sampler {
	s := &sampler{r: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
	s.harvest(re)
	return s
}

func (s *sampler) harvest(re *syntax.Regexp) {
	if re.Op == syntax.OpLiteral {
		w := string(re.Rune)
		if len(s.words) < 40 {
			s.words = append(s.words, w)
		}
	}
	for _, sub := range re.Sub {
		s.harvest(sub)
	}
}

func (s *sampler) chance(p float64) bool { return s.r.Float64() < p }

// interesting are runes that tend to break a matcher: other forms of ASCII letters under case folding,
// two byte, three byte and four byte runes, the replacement character and the last one.
var interesting = []rune{0x80, 0xE9, 0x17F, 0x212A, 0x2603, 0xFFFD, 0x1F600, 0x10FFFF, 0xC4, 0x3A3, 0x3C3, 0x3C2}

// hot are the bytes that rules treat specially.
const hot = "\n\r\t \"'`\\=:;,._-$/+(){}[]<>#&|?!@%^*~0aZ"

func (s *sampler) pickRune(rs []rune) rune {
	n := len(rs) / 2
	if n == 0 {
		return 'a'
	}
	// mostly from the ASCII part of the class
	var ascii []int
	for i := 0; i < n; i++ {
		if rs[2*i] < 0x80 {
			ascii = append(ascii, i)
		}
	}
	i := s.r.IntN(n)
	if len(ascii) > 0 && !s.chance(0.04) {
		i = ascii[s.r.IntN(len(ascii))]
	}
	lo, hi := rs[2*i], rs[2*i+1]
	if lo < 0x80 && hi >= 0x80 && !s.chance(0.1) {
		hi = 0x7F
	}
	var r rune
	switch {
	case s.chance(0.2):
		r = lo
	case s.chance(0.25):
		r = hi
	case hi-lo > 5000: // a negated class: a handful of rules' worth of interesting runes, else something plain
		r = interesting[s.r.IntN(len(interesting))]
		if r < lo || r > hi || s.chance(0.5) {
			r = lo + rune(s.r.IntN(int(min(hi-lo+1, 95))))
		}
	default:
		r = lo + rune(s.r.IntN(int(hi-lo+1)))
	}
	if r >= 0xD800 && r <= 0xDFFF {
		r = lo
		if r >= 0xD800 && r <= 0xDFFF {
			r = 0xE000
		}
	}
	return r
}

func (s *sampler) count(min, max int) int {
	switch {
	case max >= 0 && max == min:
		return min
	case s.chance(0.25):
		return min
	case max >= 0 && s.chance(0.25):
		return max
	case max >= 0:
		return min + s.r.IntN(max-min+1)
	case s.chance(0.1):
		return min + s.r.IntN(60)
	}
	return min + s.r.IntN(8)
}

func (s *sampler) emit(b []byte, r rune) []byte { return utf8.AppendRune(b, r) }

// gen appends a string the tree matches (when no assertion gets in the way).
func (s *sampler) gen(re *syntax.Regexp, b []byte) []byte {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 {
				orbit := []rune{r}
				for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
					orbit = append(orbit, f)
				}
				r = orbit[s.r.IntN(len(orbit))]
				if r >= 0x80 && s.chance(0.7) {
					r = orbit[0]
				}
			}
			b = s.emit(b, r)
		}
	case syntax.OpCharClass:
		b = s.emit(b, s.pickRune(re.Rune))
	case syntax.OpAnyCharNotNL:
		b = s.emit(b, s.pickRune([]rune{' ', '~', 0x80, 0x10FFFF}))
	case syntax.OpAnyChar:
		if s.chance(0.05) {
			b = append(b, '\n')
		} else {
			b = s.emit(b, s.pickRune([]rune{' ', '~', 0x80, 0x10FFFF}))
		}
	case syntax.OpCapture:
		b = s.gen(re.Sub[0], b)
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			b = s.gen(sub, b)
		}
	case syntax.OpAlternate:
		b = s.gen(re.Sub[s.r.IntN(len(re.Sub))], b)
	case syntax.OpQuest:
		if s.chance(0.5) {
			b = s.gen(re.Sub[0], b)
		}
	case syntax.OpStar:
		for i, n := 0, s.count(0, -1); i < n; i++ {
			b = s.gen(re.Sub[0], b)
		}
	case syntax.OpPlus:
		for i, n := 0, s.count(1, -1); i < n; i++ {
			b = s.gen(re.Sub[0], b)
		}
	case syntax.OpRepeat:
		for i, n := 0, s.count(re.Min, re.Max); i < n; i++ {
			b = s.gen(re.Sub[0], b)
		}
	}
	return b
}

// noise is text that has nothing to do with the pattern, or a little to do with it.
func (s *sampler) noise(b []byte) []byte {
	for n := s.r.IntN(12); n > 0; n-- {
		switch k := s.r.IntN(10); {
		case k < 3:
			b = append(b, hot[s.r.IntN(len(hot))])
		case k < 5:
			b = append(b, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"[s.r.IntN(63)])
		case k < 7 && len(s.words) > 0:
			w := s.words[s.r.IntN(len(s.words))]
			switch s.r.IntN(3) {
			case 0:
				w = strings.ToUpper(w)
			case 1:
				w = strings.ToLower(w)
			}
			b = append(b, w...)
		case k < 8:
			b = s.emit(b, interesting[s.r.IntN(len(interesting))])
		case k < 9:
			b = append(b, byte(0x80+s.r.IntN(0x80))) // a byte that is not UTF-8 by itself
		default:
			b = append(b, " \n"[s.r.IntN(2)])
		}
	}
	return b
}

// mutate changes an input in a small way.
func (s *sampler) mutate(b []byte) []byte {
	if len(b) == 0 {
		return s.noise(b)
	}
	i := s.r.IntN(len(b))
	switch s.r.IntN(11) {
	case 0:
		b[i] = byte(s.r.IntN(256))
	case 1:
		b[i] = hot[s.r.IntN(len(hot))]
	case 2:
		b[i] += byte(s.r.IntN(3)) - 1
	case 3:
		b = append(b[:i], b[i+1:]...)
	case 4:
		j := min(len(b), i+1+s.r.IntN(12))
		b = append(b[:i], b[j:]...)
	case 5:
		ins := s.noise(nil)
		b = append(b[:i], append(ins, b[i:]...)...)
	case 6:
		j := min(len(b), i+1+s.r.IntN(40))
		seg := append([]byte(nil), b[i:j]...)
		b = append(b[:j], append(seg, b[j:]...)...)
	case 7:
		b = b[:i]
	case 8:
		if c := b[i]; c >= 'a' && c <= 'z' {
			b[i] = c - 32
		} else if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	case 9:
		ins := utf8.AppendRune(nil, interesting[s.r.IntN(len(interesting))])
		b = append(b[:i], append(ins, b[i:]...)...)
	default:
		if i+1 < len(b) {
			b[i], b[i+1] = b[i+1], b[i]
		}
	}
	return b
}

// input is one test input for the tree: usually a sample with noise around it, sometimes several, and
// often changed a little.
func (s *sampler) input(re *syntax.Regexp) []byte {
	var b []byte
	parts := 1
	if s.chance(0.25) {
		parts += 1 + s.r.IntN(3)
	}
	for ; parts > 0; parts-- {
		b = s.noise(b)
		if s.chance(0.92) {
			b = s.gen(re, b)
		}
		b = s.noise(b)
	}
	if s.chance(0.04) {
		// a long input, to see the scan skip from one place to the next and the search resume after a match
		for n := 20 + s.r.IntN(200); n > 0; n-- {
			b = s.noise(b)
			if s.chance(0.1) {
				b = s.gen(re, b)
			}
		}
	}
	for s.chance(0.6) {
		b = s.mutate(b)
	}
	return b
}
