package lin

import (
	"sort"
	"unicode/utf8"
)

// bits is a set of bytes.
type bits [4]uint64

func (s *bits) add(b byte)      { s[b>>6] |= 1 << (b & 63) }
func (s *bits) has(b byte) bool { return s[b>>6]>>(b&63)&1 != 0 }

func (s *bits) addRange(lo, hi int) {
	for b := lo; b <= hi; b++ {
		s.add(byte(b))
	}
}

func (s *bits) or(t *bits) {
	for i := range s {
		s[i] |= t[i]
	}
}

func (s *bits) meets(t *bits) bool {
	for i := range s {
		if s[i]&t[i] != 0 {
			return true
		}
	}
	return false
}

func (s *bits) count() int {
	n := 0
	for _, w := range s {
		for ; w != 0; w &= w - 1 {
			n++
		}
	}
	return n
}

// only is the byte when the set holds exactly one.
func (s *bits) only() (byte, bool) {
	if s.count() != 1 {
		return 0, false
	}
	for b := 0; b < 256; b++ {
		if s.has(byte(b)) {
			return byte(b), true
		}
	}
	return 0, false
}

// class is a set of runes, the way Go's regexp matches one: a rune of the input is decoded from UTF-8,
// and a byte that is not valid UTF-8 is the replacement character U+FFFD, one byte wide.
type class struct {
	tab    [256]bool // the ASCII members; the entries from 0x80 are false
	ranges []rune    // the members from 0x80 up, as lo, hi pairs in ascending order
	inval  bool      // U+FFFD is a member, so a byte that is not valid UTF-8 is matched too
	first  bits      // the bytes a member can start with
}

// leadByte is the first byte of r's UTF-8 form, for r that is not a surrogate.
func leadByte(r rune) byte {
	switch {
	case r < 0x80:
		return byte(r)
	case r < 0x800:
		return 0xC0 | byte(r>>6)
	case r < 0x10000:
		return 0xE0 | byte(r>>12)
	}
	return 0xF0 | byte(r>>18)
}

// newClass is the class of a syntax.OpCharClass's ranges (lo, hi pairs).
func newClass(rs []rune) *class {
	c := &class{}
	for i := 0; i+1 < len(rs); i += 2 {
		lo, hi := rs[i], rs[i+1]
		for r := lo; r <= hi && r < 0x80; r++ {
			c.tab[r] = true
			c.first.add(byte(r))
		}
		if hi < 0x80 {
			continue
		}
		lo = max(lo, 0x80)
		if lo <= hi && lo <= 0xFFFD && 0xFFFD <= hi {
			c.inval = true
		}
		// A surrogate is never decoded from input (it reads as an invalid byte), and its encoding
		// would put the wrong lead byte at a bound, so the range is cut to the runes that can occur.
		if lo >= 0xD800 && lo <= 0xDFFF {
			lo = 0xE000
		}
		if hi >= 0xD800 && hi <= 0xDFFF {
			hi = 0xD7FF
		}
		if lo > hi {
			continue
		}
		c.ranges = append(c.ranges, lo, hi)
		c.first.addRange(int(leadByte(lo)), int(leadByte(hi)))
	}
	if c.inval {
		c.first.addRange(0x80, 0xFF)
	}
	return c
}

// has says whether the rune r is a member.
func (c *class) has(r rune) bool {
	if r < 0x80 {
		return r >= 0 && c.tab[r]
	}
	n := len(c.ranges) / 2
	if n <= 8 {
		for i := 0; i < len(c.ranges); i += 2 {
			if r < c.ranges[i] {
				return false
			}
			if r <= c.ranges[i+1] {
				return true
			}
		}
		return false
	}
	i := sort.Search(n, func(i int) bool { return c.ranges[2*i+1] >= r })
	return i < n && c.ranges[2*i] <= r
}

// slow is the width of the rune at b[q] when it is a member, else 0, for a byte from 0x80 up.
func (c *class) slow(b []byte, q int) int {
	r, w := utf8.DecodeRune(b[q:])
	if r == utf8.RuneError && w == 1 {
		if c.inval {
			return 1
		}
		return 0
	}
	if c.has(r) {
		return w
	}
	return 0
}

// at is the width of the rune at b[q] when it is a member, else 0. q is inside b.
func (c *class) at(b []byte, q int) int {
	if x := b[q]; x < 0x80 {
		if c.tab[x] {
			return 1
		}
		return 0
	}
	return c.slow(b, q)
}

// asciiOnly says that every member is ASCII, so a run of the class never holds a multi-byte rune.
func (c *class) asciiOnly() bool { return len(c.ranges) == 0 && !c.inval }
