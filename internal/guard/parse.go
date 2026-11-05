package guard

import (
	"errors"
	"strings"
)

// The parser reads the subset of POSIX/bash shell that decides which programs run and
// with which arguments: quoting, escapes, command substitution, here-documents, and the
// separators ; && || | & and newline. It is deliberately not a full shell. What it
// cannot read it either skips (variables expand to nothing it can see) or reports as a
// parse error, and the guard allows on a parse error (dcg and guard.py still stand
// behind it).

// word is one shell word after quote removal. subs are the command substitutions inside
// it that really run: $(...), `...` and <(...) outside single quotes.
type word struct {
	text   string
	subs   []*script
	quoted bool
}

// heredoc is a <<DELIM redirection. Its body is data unless the command is a shell, but
// an unquoted delimiter means the body is expanded, so $(...) inside it still runs.
type heredoc struct {
	delim  string
	strip  bool
	expand bool
	body   string
	owner  *cmd
}

// cmd is one simple command, redirections removed.
type cmd struct {
	words    []word
	extra    []*script // substitutions in redirect targets and expanded heredoc bodies
	hereDocs []*heredoc
	hereStr  []word
	targets  []word // the files an output redirection (>, >>, >|, &>) writes
	piped    bool   // stdin is the previous command's stdout
}

type script struct{ cmds []*cmd }

const maxDepth = 12

var errParse = errors.New("shell syntax this guard cannot read")

type parser struct {
	s      string
	i      int
	depth  int
	err    error
	stable int // top-level commands complete before the current line began
}

// parse reads a command line. On a syntax error it returns what bash would already have
// run: bash executes a script one complete line at a time, so earlier lines count and
// the broken one does not.
func parse(s string) (*script, error) {
	p := &parser{s: s}
	sc := p.script(0)
	if p.err != nil {
		if p.stable < len(sc.cmds) {
			sc.cmds = sc.cmds[:p.stable]
		}
		return sc, p.err
	}
	return sc, nil
}

func (p *parser) fail() {
	if p.err == nil {
		p.err = errParse
	}
}

func (p *parser) eof() bool { return p.i >= len(p.s) }

func (p *parser) peek(n int) byte {
	if p.i+n < len(p.s) {
		return p.s[p.i+n]
	}
	return 0
}

func (p *parser) skipBlanks() {
	for p.i < len(p.s) {
		switch {
		case p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\r':
			p.i++
		case p.s[p.i] == '\\' && p.peek(1) == '\n':
			p.i += 2
		default:
			return
		}
	}
}

// script parses commands until EOF, or until the ')' that closes a $(...) when term is ')'.
func (p *parser) script(term byte) *script {
	sc := &script{}
	if p.depth > maxDepth {
		p.fail()
		return sc
	}
	p.depth++
	defer func() { p.depth-- }()

	var (
		cur      *cmd
		pending  []*heredoc
		paren    int
		pipeNext bool
	)
	current := func() *cmd {
		if cur == nil {
			cur = &cmd{piped: pipeNext}
			pipeNext = false
		}
		return cur
	}
	end := func() {
		if cur != nil && (len(cur.words) > 0 || len(cur.extra) > 0 || len(cur.hereDocs) > 0 || len(cur.hereStr) > 0 || len(cur.targets) > 0) {
			sc.cmds = append(sc.cmds, cur)
		}
		cur = nil
	}

	for p.err == nil {
		p.skipBlanks()
		if p.eof() {
			if term != 0 {
				p.fail()
			}
			break
		}
		c := p.s[p.i]
		switch {
		case c == '#':
			for !p.eof() && p.s[p.i] != '\n' {
				p.i++
			}
		case c == '\n':
			p.i++
			end()
			for _, h := range pending {
				p.readHeredoc(h)
			}
			pending = nil
			if term == 0 && paren == 0 {
				p.stable = len(sc.cmds)
			}
		case c == ';':
			p.i++
			if n := p.peek(0); n == ';' || n == '&' {
				p.i++
			}
			end()
		case c == '&' && p.peek(1) == '>':
			p.redirect(current, &pending)
		case c == '&':
			p.i++
			if p.peek(0) == '&' {
				p.i++
			}
			end()
		case c == '|':
			p.i++
			if p.peek(0) == '|' {
				p.i++
				end()
			} else {
				if p.peek(0) == '&' {
					p.i++
				}
				end()
				pipeNext = true
			}
		case c == '(':
			p.i++
			paren++
			end()
		case c == ')':
			p.i++
			end()
			if paren > 0 {
				paren--
			} else if term == ')' {
				return sc
			}
		case (c == '<' || c == '>') && p.peek(1) != '(':
			p.redirect(current, &pending)
		default:
			w := p.word()
			// "2>file": the digits belong to the redirection, not to the command.
			if n := p.peek(0); (n == '<' || n == '>') && !w.quoted && isDigits(w.text) {
				continue
			}
			cm := current()
			cm.words = append(cm.words, w)
		}
	}
	end()
	return sc
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// redirect consumes one redirection operator and its target. Targets are dropped (they
// are file names), except that substitutions inside them still run, and << / <<< carry a
// body or string that a shell command would execute.
func (p *parser) redirect(current func() *cmd, pending *[]*heredoc) {
	c := current()
	op := ""
	writes := false // the target is a file the command writes
	switch ch := p.s[p.i]; {
	case ch == '&': // &> and &>>
		p.i += 2
		writes = true
		if p.peek(0) == '>' {
			p.i++
		}
	default:
		p.i++
		writes = ch == '>'
		switch n := p.peek(0); {
		case n == ch && ch == '<':
			p.i++
			op = "<<"
			if p.peek(0) == '<' {
				p.i++
				op = "<<<"
			} else if p.peek(0) == '-' {
				p.i++
				op = "<<-"
			}
		case n == ch: // >>
			p.i++
		case n == '&' || n == '|' || (ch == '<' && n == '>'):
			p.i++
			writes = writes || n == '>'
		}
	}
	p.skipBlanks()
	if p.eof() {
		return
	}
	if k := p.s[p.i]; k == '\n' || k == ';' || k == '|' || k == '&' || k == ')' {
		return // an operator with no target; the shell would reject it, we move on
	}
	w := p.word()
	switch op {
	case "<<", "<<-":
		h := &heredoc{delim: w.text, strip: op == "<<-", expand: !w.quoted, owner: c}
		c.hereDocs = append(c.hereDocs, h)
		*pending = append(*pending, h)
	case "<<<":
		c.hereStr = append(c.hereStr, w)
		c.extra = append(c.extra, w.subs...)
	default:
		c.extra = append(c.extra, w.subs...)
		// `>&2` and `>&-` duplicate a descriptor; every other target is a file.
		if writes && w.text != "" && !isDigits(w.text) && w.text != "-" {
			c.targets = append(c.targets, w)
		}
	}
}

// readHeredoc reads the body after the newline that follows its operator.
func (p *parser) readHeredoc(h *heredoc) {
	var lines []string
	for p.i < len(p.s) {
		line := p.s[p.i:]
		if j := strings.IndexByte(line, '\n'); j >= 0 {
			line = line[:j]
			p.i += j + 1
		} else {
			p.i = len(p.s)
		}
		if h.strip {
			line = strings.TrimLeft(line, "\t")
		}
		if strings.TrimSuffix(line, "\r") == h.delim {
			break
		}
		lines = append(lines, line)
	}
	h.body = strings.Join(lines, "\n")
	if h.expand {
		h.owner.extra = append(h.owner.extra, p.expansions(h.body)...)
	}
}

// expansions finds the command substitutions an expanded heredoc body would run.
func (p *parser) expansions(body string) []*script {
	q := &parser{s: body, depth: p.depth}
	var out []*script
	for q.i < len(q.s) && q.err == nil {
		switch q.s[q.i] {
		case '\\':
			q.i += 2
		case '`':
			out = append(out, q.backtick())
		case '$':
			switch {
			case q.peek(1) == '(' && q.peek(2) == '(':
				q.arith()
			case q.peek(1) == '(':
				q.i += 2
				out = append(out, q.script(')'))
			default:
				q.i++
			}
		default:
			q.i++
		}
	}
	return out // a broken substitution inside data is data
}

// word reads one word, resolving quotes and escapes.
func (p *parser) word() word {
	var b strings.Builder
	var w word
	for p.i < len(p.s) && p.err == nil {
		c := p.s[p.i]
		switch c {
		case ' ', '\t', '\n', '\r', ';', '&', '|', '(', ')':
			w.text = b.String()
			return w
		case '<', '>':
			if p.peek(1) != '(' || b.Len() > 0 {
				w.text = b.String()
				return w
			}
			p.i += 2 // process substitution runs its command
			w.subs = append(w.subs, p.script(')'))
			b.WriteString("<(…)")
		case '\\':
			switch {
			case p.peek(1) == '\n':
				p.i += 2
			case p.i+1 < len(p.s):
				b.WriteByte(p.s[p.i+1])
				p.i += 2
				w.quoted = true
			default:
				b.WriteByte('\\')
				p.i++
			}
		case '\'':
			w.quoted = true
			j := strings.IndexByte(p.s[p.i+1:], '\'')
			if j < 0 {
				p.fail()
				break
			}
			b.WriteString(p.s[p.i+1 : p.i+1+j])
			p.i += j + 2
		case '"':
			w.quoted = true
			p.i++
			p.dquote(&b, &w)
		case '$':
			p.dollar(&b, &w, false)
		case '`':
			w.subs = append(w.subs, p.backtick())
			b.WriteString("`…`")
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	w.text = b.String()
	return w
}

// dquote reads the inside of a double-quoted string; the opening quote is consumed.
func (p *parser) dquote(b *strings.Builder, w *word) {
	for p.i < len(p.s) && p.err == nil {
		switch c := p.s[p.i]; c {
		case '"':
			p.i++
			return
		case '\\':
			if p.i+1 >= len(p.s) {
				p.i++ // a lone trailing backslash: the quote is still unterminated
				continue
			}
			switch n := p.s[p.i+1]; n {
			case '$', '`', '"', '\\':
				b.WriteByte(n)
			case '\n':
			default:
				b.WriteByte('\\')
				b.WriteByte(n)
			}
			p.i += 2
		case '$':
			p.dollar(b, w, true)
		case '`':
			w.subs = append(w.subs, p.backtick())
			b.WriteString("`…`")
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	p.fail() // ran out of input inside the quotes
}

// dollar handles a '$' at p.i. A value it cannot know (variables, command output) is
// written as a placeholder that no option or program name can match.
func (p *parser) dollar(b *strings.Builder, w *word, inQuote bool) {
	switch n := p.peek(1); {
	case n == '(' && p.peek(2) == '(':
		p.arith()
		b.WriteString("$((…))")
	case n == '(':
		p.i += 2
		w.subs = append(w.subs, p.script(')'))
		b.WriteString("$(…)")
	case n == '{':
		depth := 0
		for j := p.i + 1; j < len(p.s); j++ {
			switch p.s[j] {
			case '{':
				depth++
			case '}':
				if depth--; depth == 0 {
					p.i = j + 1
					b.WriteString("${…}")
					return
				}
			}
		}
		p.fail()
	case n == '\'' && !inQuote:
		p.i += 2
		p.ansiC(b)
	case n == '"' && !inQuote:
		p.i++ // $"..." is a translated string; the quote that follows is read next
	default:
		b.WriteByte('$')
		p.i++
	}
}

// arith skips $(( ... )) and leaves p.i after it.
func (p *parser) arith() {
	depth := 0
	for j := p.i + 2; j < len(p.s); j++ {
		switch p.s[j] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				p.i = j + 1
				return
			}
		}
	}
	p.fail()
}

// backtick reads `...` and parses its body as a script.
func (p *parser) backtick() *script {
	j := p.i + 1
	var body strings.Builder
	for ; j < len(p.s); j++ {
		switch p.s[j] {
		case '`':
			q := &parser{s: body.String(), depth: p.depth}
			sc := q.script(0)
			if q.err != nil {
				p.fail()
			}
			p.i = j + 1
			return sc
		case '\\':
			if j+1 < len(p.s) && strings.IndexByte("`\\$", p.s[j+1]) >= 0 {
				j++
			}
		}
		body.WriteByte(p.s[j])
	}
	p.fail()
	return &script{}
}

// ansiC decodes a $'...' string; p.i is just past the opening quote.
func (p *parser) ansiC(b *strings.Builder) {
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '\'':
			p.i++
			return
		case c == '\\' && p.i+1 < len(p.s):
			p.i++
			switch e := p.s[p.i]; e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case 'a':
				b.WriteByte(7)
			case 'b':
				b.WriteByte(8)
			case 'e', 'E':
				b.WriteByte(27)
			case 'f':
				b.WriteByte(12)
			case 'v':
				b.WriteByte(11)
			case 'x':
				p.i++
				v, n := p.digits(16, 2)
				b.WriteByte(byte(v))
				p.i += n - 1
			case 'u', 'U':
				limit := 4
				if e == 'U' {
					limit = 8
				}
				p.i++
				v, n := p.digits(16, limit)
				b.WriteRune(rune(v))
				p.i += n - 1
			case '0', '1', '2', '3', '4', '5', '6', '7':
				v, n := p.digits(8, 3)
				b.WriteByte(byte(v))
				p.i += n - 1
			default:
				b.WriteByte(e) // \\ \' \" \? and anything unknown
			}
			p.i++
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	p.fail()
}

// digits reads up to limit digits in base at p.i and returns the value and how many it read
// (at least 1, so a stray "\x" does not stall).
func (p *parser) digits(base, limit int) (v int64, n int) {
	for n < limit && p.i+n < len(p.s) {
		d := strings.IndexByte("0123456789abcdef", lower(p.s[p.i+n]))
		if d < 0 || d >= base {
			break
		}
		v = v*int64(base) + int64(d)
		n++
	}
	if n == 0 {
		return 0, 1
	}
	return v, n
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// Tokenize splits a command line into its simple commands, each a list of unquoted words.
// Quotes and escapes are resolved, $(...) stays inside the word it sits in, and the
// separators ; && || | & and newline end a command. Redirections are dropped. It is the
// view the rules in Decide start from, exposed for tests and tooling.
func Tokenize(command string) ([][]string, error) {
	sc, err := parse(command)
	var out [][]string
	for _, c := range sc.cmds {
		if len(c.words) == 0 { // a bare redirection, kept for the write rules
			continue
		}
		ws := make([]string, len(c.words))
		for i, w := range c.words {
			ws[i] = w.text
		}
		out = append(out, ws)
	}
	return out, err
}
