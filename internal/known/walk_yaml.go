package known

import (
	"errors"
	"strings"
)

var errYAML = errors.New("yaml: something in this file could not be read")

// yamlLine is one line that carries content.
type yamlLine struct {
	no     int    // 0-based index into the raw lines
	indent int    // leading blanks
	text   string // comment stripped, trimmed
}

// yamlReader is a tolerant reader of the block YAML that config files use: nested mappings,
// sequences of scalars and of mappings, flow collections, quoted and plain scalars, block
// scalars. It does not validate and does not follow anchors; it finds the strings and the
// keys above them.
type yamlReader struct {
	raw   []string
	lines []yamlLine
	w     *walker
	err   error
}

func walkYAML(data []byte, w *walker) error {
	y := &yamlReader{w: w}
	y.raw = strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for i, l := range y.raw {
		trimmed := strings.TrimLeft(l, " \t")
		text := strings.TrimSpace(stripYAMLComment(trimmed))
		if text == "" || text == "---" || text == "..." || strings.HasPrefix(text, "%") {
			continue
		}
		y.lines = append(y.lines, yamlLine{no: i, indent: len(l) - len(trimmed), text: text})
	}
	y.run()
	return y.err
}

func (y *yamlReader) fail() {
	if y.err == nil {
		y.err = errYAML
	}
}

// stripYAMLComment cuts a # that starts a comment: at the start of the text or after white
// space, outside quotes. A quote only opens a string at the start of a token, so the
// apostrophe in "don't" opens nothing.
func stripYAMLComment(s string) string {
	var quote byte
	prev := byte(' ')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case (c == '"' || c == '\'') && strings.IndexByte(" \t[{,:-", prev) >= 0:
			quote = c
		case c == '#' && (prev == ' ' || prev == '\t'):
			return s[:i]
		}
		prev = c
	}
	return s
}

type yframe struct {
	indent  int
	seg     string
	sameSeq bool // the key's sequence items sit at the key's own indent
}

func (y *yamlReader) run() {
	var st []yframe
	pathOf := func() []string {
		p := make([]string, 0, len(st)+1)
		for _, f := range st {
			p = append(p, f.seg)
		}
		return p
	}
	for i := 0; i < len(y.lines); i++ {
		ln := y.lines[i]
		text, ind := ln.text, ln.indent
		isDash := text == "-" || strings.HasPrefix(text, "- ")
		for len(st) > 0 {
			top := st[len(st)-1]
			if top.indent > ind || top.indent == ind && !(isDash && top.sameSeq) {
				st = st[:len(st)-1]
				continue
			}
			break
		}
		// Sequence items: "- key: v" starts a mapping, "- - x" a nested sequence, "- x" is a
		// scalar item that no key above collected.
		for text == "-" || strings.HasPrefix(text, "- ") {
			rest := strings.TrimLeft(text[1:], " ")
			col := ind + len(text) - len(rest)
			if rest == "" || isMappingLine(rest) || rest == "-" || strings.HasPrefix(rest, "- ") {
				st = append(st, yframe{indent: ind, seg: "[]"})
				ind, text = col, rest
				continue
			}
			y.w.list(pathOf(), []elem{{v: y.scalarText(rest), line: ln.no + 1, ok: true}})
			text = ""
			break
		}
		if text == "" {
			continue
		}
		key, rest, ok := splitYAMLKey(text)
		if !ok {
			continue // prose, a continuation line
		}
		path := with(pathOf(), key)
		rest = stripYAMLProps(rest)
		switch {
		case rest == "":
			if n := y.scalarList(i+1, ind, path); n > 0 {
				i += n
				continue
			}
			st = append(st, yframe{indent: ind, seg: key, sameSeq: i+1 < len(y.lines) && y.lines[i+1].indent == ind && strings.HasPrefix(y.lines[i+1].text, "-")})
		case rest[0] == '|' || rest[0] == '>':
			body, used := y.blockScalar(i, ind)
			y.w.value(path, body, ln.no+1)
			i += used
		case rest[0] == '[' || rest[0] == '{':
			flow, used := y.flowText(i, rest)
			f := &flowReader{s: flow, line: ln.no + 1, w: y.w}
			f.value(path, 0)
			if f.bad {
				y.fail()
			}
			i += used
		case rest[0] == '*': // an alias
		default:
			y.w.value(path, y.scalarText(rest), ln.no+1)
		}
	}
}

// scalarList reads the scalar items of the sequence that follows a key with no value, from
// line from on, and reports how many lines it used. A sequence of mappings is left to the
// main loop.
func (y *yamlReader) scalarList(from, keyIndent int, path []string) int {
	if from >= len(y.lines) {
		return 0
	}
	first := y.lines[from]
	if first.indent < keyIndent || first.indent == keyIndent && !(first.text == "-" || strings.HasPrefix(first.text, "- ")) {
		return 0
	}
	var es []elem
	n := 0
	for j := from; j < len(y.lines); j++ {
		l := y.lines[j]
		if l.indent != first.indent || !(strings.HasPrefix(l.text, "- ") && len(l.text) > 2) {
			break
		}
		item := strings.TrimSpace(l.text[2:])
		if isMappingLine(item) || strings.HasPrefix(item, "- ") || item == "-" {
			return 0 // a sequence of mappings: not ours
		}
		if len(es) < maxListElems {
			es = append(es, elem{v: y.scalarText(item), line: l.no + 1, ok: true})
		}
		n++
	}
	if n == 0 {
		return 0
	}
	y.w.list(path, es)
	return n
}

// scalarText turns the text of a scalar into its string: quotes removed, escapes decoded.
func (y *yamlReader) scalarText(s string) string {
	s = stripYAMLProps(s)
	if len(s) >= 2 && s[0] == '"' {
		if end := closingQuote(s, '"'); end > 0 {
			return unescapeDouble(s[1:end])
		}
		return unescapeDouble(s[1:])
	}
	if len(s) >= 2 && s[0] == '\'' {
		if end := closingQuote(s, '\''); end > 0 {
			return strings.ReplaceAll(s[1:end], "''", "'")
		}
		return s[1:]
	}
	return s
}

// closingQuote finds the quote that ends the string opening at s[0].
func closingQuote(s string, q byte) int {
	for i := 1; i < len(s); i++ {
		switch {
		case q == '"' && s[i] == '\\':
			i++
		case s[i] == q && q == '\'' && i+1 < len(s) && s[i+1] == '\'':
			i++
		case s[i] == q:
			return i
		}
	}
	return -1
}

// stripYAMLProps drops an anchor (&name) or a tag (!tag, !!str) in front of a value.
func stripYAMLProps(s string) string {
	for {
		s = strings.TrimLeft(s, " \t")
		if s != "" && (s[0] == '&' || s[0] == '!') {
			if sp := strings.IndexAny(s, " \t"); sp > 0 {
				s = s[sp:]
				continue
			}
			return ""
		}
		return s
	}
}

// isMappingLine: the text is "key: value" or "key:" (a key that opens a block).
func isMappingLine(s string) bool {
	_, _, ok := splitYAMLKey(s)
	return ok
}

// splitYAMLKey cuts "key: rest". The key is a quoted string or the plain text before the
// first ": " (or a colon at the end of the line).
func splitYAMLKey(text string) (key, rest string, ok bool) {
	if text == "" || strings.ContainsRune("-[{&*!|>#%@`", rune(text[0])) && !(text[0] == '-' && len(text) > 1 && text[1] != ' ') {
		return "", "", false
	}
	if text[0] == '"' || text[0] == '\'' {
		end := closingQuote(text, text[0])
		if end < 0 {
			return "", "", false
		}
		after := strings.TrimLeft(text[end+1:], " \t")
		if !strings.HasPrefix(after, ":") {
			return "", "", false
		}
		return y2s(text[:end+1]), strings.TrimSpace(after[1:]), true
	}
	for i := 0; i < len(text); i++ {
		if text[i] != ':' {
			continue
		}
		if i+1 == len(text) || text[i+1] == ' ' || text[i+1] == '\t' {
			k := strings.TrimSpace(text[:i])
			if k == "" {
				return "", "", false
			}
			return k, strings.TrimSpace(text[i+1:]), true
		}
	}
	return "", "", false
}

// y2s unquotes a quoted key.
func y2s(q string) string {
	if q[0] == '"' {
		return unescapeDouble(q[1 : len(q)-1])
	}
	return strings.ReplaceAll(q[1:len(q)-1], "''", "'")
}

// blockScalar reads the | or > block under the key on line i (key indent ind): every
// following line that is more indented than the key. It returns the text and the number of
// extra lines used.
func (y *yamlReader) blockScalar(i, ind int) (string, int) {
	var b strings.Builder
	used := 0
	for j := i + 1; j < len(y.lines); j++ {
		if y.lines[j].indent <= ind {
			break
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(y.lines[j].text)
		used++
	}
	return b.String(), used
}

// flowText returns the flow collection that starts the value of line i, continued over
// following lines until its brackets balance (at most 200 lines).
func (y *yamlReader) flowText(i int, rest string) (string, int) {
	text, used := rest, 0
	for depthOf(text) > 0 && i+used+1 < len(y.lines) && used < 200 {
		used++
		text += " " + y.lines[i+used].text
	}
	return text, used
}

// depthOf counts unclosed [ and { outside quotes.
func depthOf(s string) int {
	d := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '[' || c == '{':
			d++
		case c == ']' || c == '}':
			d--
		}
	}
	return d
}

// flowReader reads a YAML flow collection: [a, b, {k: v}].
type flowReader struct {
	s    string
	i    int
	line int
	w    *walker
	bad  bool
}

func (f *flowReader) skip() {
	for f.i < len(f.s) && (f.s[f.i] == ' ' || f.s[f.i] == '\t') {
		f.i++
	}
}

func (f *flowReader) value(path []string, depth int) {
	f.skip()
	if f.i >= len(f.s) || depth > maxDepth {
		f.bad = f.bad || depth > maxDepth
		return
	}
	switch c := f.s[f.i]; c {
	case '[':
		f.i++
		var es []elem
		for {
			f.skip()
			if f.i >= len(f.s) {
				f.bad = true
				break
			}
			if f.s[f.i] == ']' {
				f.i++
				break
			}
			before := f.i
			switch f.s[f.i] {
			case '[', '{':
				f.value(with(path, "[]"), depth+1)
				es = append(es, elem{})
			default:
				if v, ok := f.scalar(false); ok && len(es) < maxListElems {
					es = append(es, elem{v: v, line: f.line, ok: true})
				}
			}
			f.skip()
			if f.i < len(f.s) && f.s[f.i] == ',' {
				f.i++
			}
			if f.i == before {
				f.i++
			}
		}
		f.w.list(path, es)
	case '{':
		f.i++
		for {
			f.skip()
			if f.i >= len(f.s) {
				f.bad = true
				return
			}
			if f.s[f.i] == '}' {
				f.i++
				return
			}
			before := f.i
			key, ok := f.scalar(true)
			f.skip()
			if !ok || f.i >= len(f.s) || f.s[f.i] != ':' {
				f.bad = true
				f.i = len(f.s)
				return
			}
			f.i++
			f.value(with(path, key), depth+1)
			f.skip()
			if f.i < len(f.s) && f.s[f.i] == ',' {
				f.i++
			}
			if f.i == before {
				f.i++
			}
		}
	default:
		if v, ok := f.scalar(false); ok {
			f.w.value(path, v, f.line)
		}
	}
}

// scalar reads a quoted or plain scalar; as a key it stops at a colon.
func (f *flowReader) scalar(key bool) (string, bool) {
	f.skip()
	if f.i >= len(f.s) {
		return "", false
	}
	if c := f.s[f.i]; c == '"' || c == '\'' {
		end := closingQuote(f.s[f.i:], c)
		if end < 0 {
			f.bad = true
			v := f.s[f.i+1:]
			f.i = len(f.s)
			return v, true
		}
		body := f.s[f.i+1 : f.i+end]
		f.i += end + 1
		if c == '"' {
			return unescapeDouble(body), true
		}
		return strings.ReplaceAll(body, "''", "'"), true
	}
	start := f.i
	for f.i < len(f.s) {
		c := f.s[f.i]
		if c == ',' || c == '}' || c == ']' || key && c == ':' && (f.i+1 >= len(f.s) || f.s[f.i+1] == ' ') {
			break
		}
		f.i++
	}
	return strings.TrimSpace(f.s[start:f.i]), f.i > start
}
