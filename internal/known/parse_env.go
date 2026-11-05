package known

import (
	"strings"
)

// maxQuotedLines bounds a quoted value that runs over several lines, so one stray quote
// cannot swallow the rest of the file as a single value.
const maxQuotedLines = 200

// parseDotenv reads KEY=VALUE files: an optional export, single, double and backtick
// quotes, inline comments after whitespace, spaces around the =, and quoted values that
// run over several lines.
func parseDotenv(l *learner, path string, data []byte) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || line[0] == '#' {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "export"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			line = strings.TrimSpace(rest)
		}
		name, rest, ok := cutAssign(line)
		if !ok {
			continue
		}
		vals, used := dotenvValue(strings.TrimLeft(rest, " \t"), lines[i+1:])
		for _, v := range vals {
			l.ingest(name, v, path, false)
		}
		if used > 0 {
			// A quote that runs over lines may be a typo that swallowed real assignments
			// (a stray " in one value closes at the next one). Read the lines inside again
			// as ordinary lines so none of their secrets is lost to it; a genuine multi-line
			// value has no NAME= lines in it, so this adds nothing there.
			parseDotenv(l, path, []byte(strings.Join(lines[i+1:i+1+used], "\n")))
		}
		i += used
	}
}

// cutAssign splits NAME=VALUE (spaces allowed around the =). Names follow what dotenv
// libraries accept: letters, digits, underscore, dot and dash, not starting with a digit.
func cutAssign(line string) (name, value string, ok bool) {
	i := 0
	for i < len(line) {
		c := line[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || i > 0 && (c >= '0' && c <= '9' || c == '.' || c == '-') {
			i++
			continue
		}
		break
	}
	if i == 0 {
		return "", "", false
	}
	rest := strings.TrimLeft(line[i:], " \t")
	if !strings.HasPrefix(rest, "=") {
		return "", "", false
	}
	return line[:i], rest[1:], true
}

// dotenvValue parses the right-hand side. For a double-quoted value it returns the value
// with escapes expanded and, when that differs, the text as written, because the file
// holds one and the program that reads it holds the other.
func dotenvValue(rest string, following []string) (vals []string, extraLines int) {
	if rest == "" {
		return nil, 0
	}
	q := rest[0]
	if q != '"' && q != '\'' && q != '`' {
		return []string{strings.TrimSpace(cutInlineComment(rest))}, 0
	}
	body, used, closed := readQuoted(rest[1:], q, following)
	if !closed {
		// An unterminated quote is a typo, not a value that owns the rest of the file.
		return []string{strings.TrimSpace(cutInlineComment(rest[1:]))}, 0
	}
	if q == '"' {
		if exp := unescapeDouble(body); exp != body {
			return []string{exp, body}, used
		}
	}
	return []string{body}, used
}

// readQuoted finds the closing quote, continuing onto following lines when needed.
func readQuoted(first string, q byte, following []string) (body string, extraLines int, closed bool) {
	var sb strings.Builder
	cur := first
	for n := 0; ; n++ {
		for i := 0; i < len(cur); i++ {
			if q == '"' && cur[i] == '\\' && i+1 < len(cur) {
				sb.WriteByte(cur[i])
				sb.WriteByte(cur[i+1])
				i++
				continue
			}
			if cur[i] == q {
				return sb.String(), n, true
			}
			sb.WriteByte(cur[i])
		}
		if n >= len(following) || n >= maxQuotedLines {
			return "", 0, false
		}
		sb.WriteByte('\n')
		cur = following[n]
	}
}

func unescapeDouble(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			sb.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			sb.WriteByte('\n')
		case 'r':
			sb.WriteByte('\r')
		case 't':
			sb.WriteByte('\t')
		case '"', '\\', '$', '\'', '`':
			sb.WriteByte(s[i])
		default:
			sb.WriteByte('\\')
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

// cutInlineComment drops " # ..." the way dotenv libraries do: a # only starts a comment
// after whitespace, so a value like abc#def is kept whole.
func cutInlineComment(s string) string {
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			return s[:i]
		}
	}
	return s
}

// shellWord is one word of a shell statement.
type shellWord struct {
	text    string // after quote removal
	raw     string // as written, for expanding ~ and $HOME in source lines
	dynamic bool   // contains $var, $(...) or backticks: the value is not in the file
}

// tokenizeShell splits shell source into statements of words. It understands quoting,
// comments, line continuations, and statement separators; it does not run or expand
// anything, which is the point: a dynamic word is reported as dynamic, never evaluated.
func tokenizeShell(src string) [][]shellWord {
	var stmts [][]shellWord
	var cur []shellWord
	var text, raw strings.Builder
	dynamic, inWord := false, false
	flushWord := func() {
		if inWord {
			cur = append(cur, shellWord{text.String(), raw.String(), dynamic})
			text.Reset()
			raw.Reset()
			dynamic, inWord = false, false
		}
	}
	flushStmt := func() {
		flushWord()
		if len(cur) > 0 {
			stmts = append(stmts, cur)
			cur = nil
		}
	}
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '\n' || c == ';' || c == '&' || c == '|':
			flushStmt()
		case c == ' ' || c == '\t' || c == '\r':
			flushWord()
		case c == '#' && !inWord:
			for i < len(src) && src[i] != '\n' {
				i++
			}
			flushStmt()
		case c == '\\':
			if i+1 < len(src) && src[i+1] == '\n' {
				i++ // line continuation
				continue
			}
			if i+1 < len(src) {
				i++
				text.WriteByte(src[i])
				raw.WriteByte('\\')
				raw.WriteByte(src[i])
				inWord = true
			}
		case c == '\'':
			j := strings.IndexByte(src[i+1:], '\'')
			if j < 0 {
				j = len(src) - i - 1
			}
			text.WriteString(src[i+1 : i+1+j])
			raw.WriteString(src[i:min(i+j+2, len(src))])
			inWord = true
			i += j + 1
		case c == '"':
			inWord = true
			raw.WriteByte('"')
			i++
			for ; i < len(src) && src[i] != '"'; i++ {
				ch := src[i]
				raw.WriteByte(ch)
				switch {
				case ch == '\\' && i+1 < len(src):
					i++
					raw.WriteByte(src[i])
					if strings.IndexByte("$`\"\\", src[i]) < 0 && src[i] != '\n' {
						text.WriteByte('\\')
					}
					if src[i] != '\n' {
						text.WriteByte(src[i])
					}
				case ch == '`' || ch == '$' && i+1 < len(src) && isExpansionStart(src[i+1]):
					dynamic = true
					text.WriteByte(ch)
				default:
					text.WriteByte(ch)
				}
			}
			raw.WriteByte('"')
		case c == '$' && i+1 < len(src) && src[i+1] == '\'':
			// ANSI-C quoting: $'...' with the escapes that matter for a secret.
			inWord = true
			raw.WriteString("$'")
			i += 2
			for ; i < len(src) && src[i] != '\''; i++ {
				if src[i] == '\\' && i+1 < len(src) {
					raw.WriteByte('\\')
					i++
					raw.WriteByte(src[i])
					switch src[i] {
					case 'n':
						text.WriteByte('\n')
					case 't':
						text.WriteByte('\t')
					default:
						text.WriteByte(src[i])
					}
					continue
				}
				raw.WriteByte(src[i])
				text.WriteByte(src[i])
			}
			raw.WriteByte('\'')
		default:
			inWord = true
			if c == '`' || c == '$' && i+1 < len(src) && isExpansionStart(src[i+1]) {
				dynamic = true
			}
			text.WriteByte(c)
			raw.WriteByte(c)
		}
	}
	flushStmt()
	return stmts
}

func isExpansionStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '{' || c == '(' ||
		c >= '0' && c <= '9' || strings.IndexByte("@*#?!$-", c) >= 0
}

var declarers = map[string]bool{
	"export": true, "declare": true, "typeset": true, "readonly": true, "local": true, "setenv": true,
}

// shellAssignments are the NAME=VALUE pairs a statement sets: the arguments of export and
// friends, or the assignments leading a plain statement.
func shellAssignments(stmt []shellWord) (out []shellWord, names []string) {
	i := 0
	declared := len(stmt) > 0 && declarers[stmt[0].text]
	if declared {
		i = 1
		for i < len(stmt) && strings.HasPrefix(stmt[i].text, "-") {
			i++
		}
	}
	for ; i < len(stmt); i++ {
		w := stmt[i]
		name, val, ok := strings.Cut(w.text, "=")
		name = strings.TrimSuffix(name, "+") // export PATH+=...
		if !ok || !isIdent(name) {
			if declared {
				continue // `export FOO` with no value
			}
			break
		}
		out = append(out, shellWord{text: val, raw: w.raw, dynamic: w.dynamic})
		names = append(names, name)
	}
	return out, names
}

// parseShell reads rc files for exported variables, and follows `source file` lines for
// plain paths under the home directory, two levels deep, since that is where people move
// their secrets to keep them out of the rc file.
func parseShell(l *learner, path string, data []byte) {
	l.shellDepth(path, data, 0)
}

func (l *learner) shellDepth(path string, data []byte, depth int) {
	for _, stmt := range tokenizeShell(string(data)) {
		if len(stmt) >= 2 && (stmt[0].text == "source" || stmt[0].text == ".") && depth < 2 {
			if p, ok := l.expandHome(stmt[1].raw); ok {
				l.harvestWith(p, maxEnvFile, func(l *learner, path string, data []byte) {
					l.shellDepth(path, data, depth+1)
				})
			}
			continue
		}
		vals, names := shellAssignments(stmt)
		for k, v := range vals {
			if v.dynamic {
				l.rep.Rejected["dynamic"]++
				continue
			}
			l.ingest(names[k], v.text, path, false)
		}
	}
}
