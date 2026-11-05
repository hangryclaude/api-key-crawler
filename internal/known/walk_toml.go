package known

import (
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
)

var errTOML = errors.New("toml: something in this file could not be read")

// tomlReader is a tolerant reader of the part of TOML the walker needs: tables, dotted and
// quoted keys, strings (basic, literal, multi-line), arrays, inline tables. It does not
// validate; on a construct it cannot read it skips to the next line and remembers that it
// did.
type tomlReader struct {
	s     string
	i     int
	lines *liner
	w     *walker
	err   error
}

func walkTOML(data []byte, w *walker) error {
	r := &tomlReader{s: string(data), lines: newLiner(data), w: w}
	r.run()
	return r.err
}

func (r *tomlReader) fail() {
	if r.err == nil {
		r.err = errTOML
	}
}

func (r *tomlReader) eof() bool { return r.i >= len(r.s) }

// skipSpace skips blanks within a line.
func (r *tomlReader) skipSpace() {
	for r.i < len(r.s) && (r.s[r.i] == ' ' || r.s[r.i] == '\t' || r.s[r.i] == '\r') {
		r.i++
	}
}

// skipLine moves past the end of the current line.
func (r *tomlReader) skipLine() {
	for r.i < len(r.s) && r.s[r.i] != '\n' {
		r.i++
	}
	if r.i < len(r.s) {
		r.i++
	}
}

// skipBlank skips blanks, line breaks and comments.
func (r *tomlReader) skipBlank() {
	for r.i < len(r.s) {
		switch r.s[r.i] {
		case ' ', '\t', '\r', '\n':
			r.i++
		case '#':
			r.skipLine()
		default:
			return
		}
	}
}

func (r *tomlReader) run() {
	var table []string
	for {
		r.skipBlank()
		if r.eof() {
			return
		}
		start := r.i
		if r.s[r.i] == '[' {
			array := strings.HasPrefix(r.s[r.i:], "[[")
			r.i++
			if array {
				r.i++
			}
			keys, ok := r.dottedKey()
			r.skipSpace()
			if !ok || r.eof() || r.s[r.i] != ']' {
				r.fail()
				r.skipLine()
				continue
			}
			r.i++
			if array {
				if r.eof() || r.s[r.i] != ']' {
					r.fail()
					r.skipLine()
					continue
				}
				r.i++
			}
			table = keys
			if array {
				table = with(keys, "[]")
			}
			r.endOfLine()
			continue
		}
		keys, ok := r.dottedKey()
		r.skipSpace()
		if !ok || r.eof() || r.s[r.i] != '=' {
			r.fail()
			r.skipLine()
		} else {
			r.i++
			r.value(with(table, keys...), 0)
			r.endOfLine()
		}
		if r.i == start { // always make progress
			r.i++
		}
	}
}

// endOfLine accepts a comment and the line break after a statement; anything else on the
// line is damage.
func (r *tomlReader) endOfLine() {
	r.skipSpace()
	if r.eof() {
		return
	}
	if r.s[r.i] != '\n' && r.s[r.i] != '#' {
		r.fail()
	}
	r.skipLine()
}

func bareKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// dottedKey reads a key of one or more segments, bare or quoted, and stops before whatever
// follows it (= or ]).
func (r *tomlReader) dottedKey() ([]string, bool) {
	var keys []string
	for {
		r.skipSpace()
		if r.eof() {
			return keys, false
		}
		var seg string
		switch c := r.s[r.i]; {
		case c == '"' || c == '\'':
			v, ok := r.quoted(c)
			if !ok {
				return keys, false
			}
			seg = v
		case bareKeyByte(c):
			j := r.i
			for j < len(r.s) && bareKeyByte(r.s[j]) {
				j++
			}
			seg, r.i = r.s[r.i:j], j
		default:
			return keys, false
		}
		keys = append(keys, seg)
		r.skipSpace()
		if !r.eof() && r.s[r.i] == '.' {
			r.i++
			continue
		}
		return keys, true
	}
}

// quoted reads a single-line string whose opening quote q is at r.i.
func (r *tomlReader) quoted(q byte) (string, bool) {
	r.i++
	var b strings.Builder
	for r.i < len(r.s) {
		c := r.s[r.i]
		switch {
		case c == q:
			r.i++
			return b.String(), true
		case c == '\n':
			return "", false
		case c == '\\' && q == '"' && r.i+1 < len(r.s):
			r.i++
			r.escape(&b)
		default:
			b.WriteByte(c)
			r.i++
		}
	}
	return "", false
}

// escape decodes the escape whose letter is at r.i.
func (r *tomlReader) escape(b *strings.Builder) {
	c := r.s[r.i]
	r.i++
	switch c {
	case 'n':
		b.WriteByte('\n')
	case 't':
		b.WriteByte('\t')
	case 'r':
		b.WriteByte('\r')
	case 'b':
		b.WriteByte('\b')
	case 'f':
		b.WriteByte('\f')
	case 'u', 'U':
		n := 4
		if c == 'U' {
			n = 8
		}
		if r.i+n <= len(r.s) {
			if v, err := strconv.ParseUint(r.s[r.i:r.i+n], 16, 32); err == nil && utf8.ValidRune(rune(v)) {
				b.WriteRune(rune(v))
				r.i += n
				return
			}
		}
		b.WriteByte(c)
	case '\n': // a line-ending backslash trims the white space that follows
		for r.i < len(r.s) && (r.s[r.i] == ' ' || r.s[r.i] == '\t' || r.s[r.i] == '\n' || r.s[r.i] == '\r') {
			r.i++
		}
	default:
		b.WriteByte(c)
	}
}

// multiline reads a triple-quoted string (basic or literal) whose opening quotes are at r.i.
func (r *tomlReader) multiline(q byte) (string, bool) {
	r.i += 3
	if strings.HasPrefix(r.s[r.i:], "\r\n") {
		r.i += 2
	} else if r.i < len(r.s) && r.s[r.i] == '\n' {
		r.i++
	}
	var b strings.Builder
	for r.i < len(r.s) {
		c := r.s[r.i]
		switch {
		case c == q && strings.HasPrefix(r.s[r.i:], string([]byte{q, q, q})):
			r.i += 3
			for r.i < len(r.s) && r.s[r.i] == q { // up to two quotes may precede the closing ones
				b.WriteByte(q)
				r.i++
			}
			return b.String(), true
		case c == '\\' && q == '"' && r.i+1 < len(r.s):
			r.i++
			r.escape(&b)
		default:
			b.WriteByte(c)
			r.i++
		}
	}
	return "", false
}

func (r *tomlReader) str(q byte) (string, bool) {
	if strings.HasPrefix(r.s[r.i:], string([]byte{q, q, q})) {
		return r.multiline(q)
	}
	return r.quoted(q)
}

const maxDepth = 64

func (r *tomlReader) value(path []string, depth int) {
	r.skipSpace()
	if r.eof() {
		r.fail()
		return
	}
	if depth > maxDepth {
		r.fail()
		r.i = len(r.s)
		return
	}
	line := r.lines.at(r.i)
	switch c := r.s[r.i]; c {
	case '"', '\'':
		v, ok := r.str(c)
		if !ok {
			r.fail()
			r.skipLine()
			return
		}
		r.w.value(path, v, line)
	case '[':
		r.i++
		var es []elem
		for {
			r.skipBlank()
			if r.eof() {
				r.fail()
				break
			}
			before := r.i
			switch r.s[r.i] {
			case ']':
				r.i++
				r.w.list(path, es)
				return
			case '"', '\'':
				ln := r.lines.at(r.i)
				v, ok := r.str(r.s[r.i])
				if !ok {
					r.fail()
					r.skipLine()
					break
				}
				if len(es) < maxListElems {
					es = append(es, elem{v: v, line: ln, ok: true})
				}
			case '[', '{':
				r.value(with(path, "[]"), depth+1)
				es = append(es, elem{})
			default:
				r.scalar()
				es = append(es, elem{})
			}
			r.skipBlank()
			if !r.eof() && r.s[r.i] == ',' {
				r.i++
			} else if !r.eof() && r.s[r.i] != ']' {
				r.fail()
				r.skipLine()
			}
			if r.i == before {
				r.i++
			}
		}
		r.w.list(path, es)
	case '{':
		r.i++
		for {
			r.skipBlank()
			if r.eof() {
				r.fail()
				return
			}
			if r.s[r.i] == '}' {
				r.i++
				return
			}
			before := r.i
			keys, ok := r.dottedKey()
			r.skipSpace()
			if !ok || r.eof() || r.s[r.i] != '=' {
				r.fail()
				r.skipLine()
				return
			}
			r.i++
			r.value(with(path, keys...), depth+1)
			r.skipBlank()
			if !r.eof() && r.s[r.i] == ',' {
				r.i++
			} else if !r.eof() && r.s[r.i] != '}' {
				r.fail()
				r.skipLine()
				return
			}
			if r.i == before {
				r.i++
			}
		}
	default:
		r.scalar()
	}
}

// scalar skips a number, boolean or date, which carry no secret.
func (r *tomlReader) scalar() {
	start := r.i
	for r.i < len(r.s) && !strings.ContainsRune(",}]\n#", rune(r.s[r.i])) {
		r.i++
	}
	if r.i == start {
		r.i++
	}
}
