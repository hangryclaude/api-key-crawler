package known

import (
	"bytes"
	"strconv"
	"strings"
	"unicode/utf8"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// LineMatch is a learned secret on a line a diff adds. It holds no raw value: Context is
// the line with every learned secret replaced by its shape.
type LineMatch struct {
	Commit  string // the "commit <sha>" a `git log -p` diff belongs to; "" for a plain diff
	Path    string // path in the new tree
	Line    int    // 1-based line number in the new file
	Context string // ≤ 200 runes around the match, secrets replaced by their shape
	core.KnownMatch
	// Offset is the byte column within the line (after the diff's +/space prefix), not an
	// offset into the diff.
}

// MatchDiff finds learned secrets on the added lines of a unified diff: `git diff
// --cached -U0`, `git diff A..B`, or `git log -p [--cc] -U0` output. Removed and context
// lines never count, since a secret that is leaving is not a leak. Combined merge diffs
// (--cc, -c) are understood: a line counts as added when it differs from any parent.
//
// The whole diff is scanned once first, so the common case, a clean diff, costs the
// matcher's speed and nothing more.
func (m *Matcher) MatchDiff(diff []byte) []LineMatch {
	hits, _ := m.MatchLimit(diff, 0)
	if len(hits) == 0 {
		return nil
	}
	var (
		out    []LineMatch
		commit string
		path   string
		in     bool  // inside a hunk's content lines
		width  int   // prefix columns: 1, or the number of parents of a combined diff
		rem    []int // lines still owed per parent column, then the result
		newLn  int   // new-file line number of the next result line
		hi     int   // first hit not yet placed
	)
	for pos := 0; pos < len(diff); {
		end, next := len(diff), len(diff)
		if nl := bytes.IndexByte(diff[pos:], '\n'); nl >= 0 {
			end, next = pos+nl, pos+nl+1
		}
		line := diff[pos:end]
		if in && len(line) > 0 && line[0] == '\\' { // "\ No newline at end of file" belongs to the line above
			pos = next
			continue
		}
		if in && len(line) >= width && validPrefix(line[:width]) {
			p := line[:width]
			for i := 0; i < width; i++ {
				if p[i] != '+' {
					rem[i]--
				}
			}
			if bytes.IndexByte(p, '-') < 0 { // the line exists in the result
				rem[width]--
				ln := newLn
				newLn++
				if bytes.IndexByte(p, '+') >= 0 {
					cs := pos + width
					for hi < len(hits) && hits[hi].Offset < cs {
						hi++
					}
					var here []core.KnownMatch
					for hi < len(hits) && hits[hi].Offset < end {
						h := hits[hi]
						h.Offset -= cs
						here = append(here, h)
						hi++
					}
					for i := range here {
						out = append(out, LineMatch{
							Commit: commit, Path: path, Line: ln,
							Context:    lineContext(diff[cs:end], here, i),
							KnownMatch: here[i],
						})
					}
				}
			}
			in = false
			for _, r := range rem {
				if r > 0 {
					in = true
				}
			}
			pos = next
			continue
		}
		in = false
		switch {
		case bytes.HasPrefix(line, []byte("commit ")):
			if sha := strings.Fields(string(line[7:])); len(sha) > 0 && isHex(sha[0]) {
				commit, path = sha[0], ""
			}
		case bytes.HasPrefix(line, []byte("diff --cc ")):
			path = diffPath(string(line[len("diff --cc "):]), false)
		case bytes.HasPrefix(line, []byte("diff --combined ")):
			path = diffPath(string(line[len("diff --combined "):]), false)
		case bytes.HasPrefix(line, []byte("diff --git ")):
			path = ""
		case bytes.HasPrefix(line, []byte("+++ ")):
			path = diffPath(string(line[4:]), true)
		case bytes.HasPrefix(line, []byte("@@")):
			if w, r, start, ok := parseHunk(line); ok {
				width, rem, newLn = w, r, start
				for _, c := range rem {
					if c > 0 {
						in = true
					}
				}
			}
		}
		pos = next
	}
	return out
}

// validPrefix reports whether b is made only of the diff prefix characters.
func validPrefix(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	if len(s) < 7 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// parseHunk reads "@@ -a,b +c,d @@" (or "@@@ -a,b -c,d +e,f @@@" for a merge with two
// parents). It returns the prefix width, how many lines each column and the result still
// owe, and the first line number of the result.
func parseHunk(line []byte) (width int, rem []int, start int, ok bool) {
	k := 0
	for k < len(line) && line[k] == '@' {
		k++
	}
	if k < 2 {
		return 0, nil, 0, false
	}
	rest := string(line[k:])
	closer := strings.Repeat("@", k)
	i := strings.Index(rest, closer)
	if i < 0 {
		return 0, nil, 0, false
	}
	fields := strings.Fields(rest[:i])
	width = k - 1
	if len(fields) != width+1 {
		return 0, nil, 0, false
	}
	rem = make([]int, width+1)
	for j, f := range fields {
		want := byte('-')
		if j == width {
			want = '+'
		}
		if f == "" || f[0] != want {
			return 0, nil, 0, false
		}
		a, b, hasCount := strings.Cut(f[1:], ",")
		s, err := strconv.Atoi(a)
		if err != nil {
			return 0, nil, 0, false
		}
		n := 1
		if hasCount {
			if n, err = strconv.Atoi(b); err != nil {
				return 0, nil, 0, false
			}
		}
		rem[j] = n
		if j == width {
			start = s
		}
	}
	return width, rem, start, true
}

// diffPath turns the path of a "+++ b/x" or "diff --cc x" line into a repo path: C-style
// quoting undone, the trailing tab git adds after names with spaces dropped, and the
// one-letter directory prefix (b/, w/, i/, c/) removed. /dev/null is a deleted file.
func diffPath(s string, prefixed bool) string {
	s = strings.TrimRight(s, "\t\r")
	if strings.HasPrefix(s, `"`) {
		if u, err := strconv.Unquote(s); err == nil {
			s = u
		}
	}
	if s == "/dev/null" {
		return ""
	}
	if prefixed && len(s) > 2 && s[1] == '/' && strings.IndexByte("abciwo", s[0]) >= 0 {
		s = s[2:]
	}
	return s
}

// lineContext shows the line around match i with every learned secret in the window
// replaced by its shape, then through fp.Context so any other token that looks random is
// masked too. Long lines (a minified bundle) are cut to the neighbourhood of the match.
func lineContext(line []byte, ms []core.KnownMatch, i int) string {
	m := ms[i]
	lo := max(0, m.Offset-80)
	hi := min(len(line), m.Offset+m.Len+80)
	for lo > 0 && !utf8.RuneStart(line[lo]) {
		lo--
	}
	for hi < len(line) && !utf8.RuneStart(line[hi]) {
		hi++
	}
	var sb strings.Builder
	if lo > 0 {
		sb.WriteString("…")
	}
	at := lo
	for _, o := range ms {
		end := min(o.Offset+o.Len, len(line))
		if end <= at || o.Offset >= hi {
			continue
		}
		// A long secret (a one-line key, a JWT) can start before the window and run into it:
		// it is still replaced whole, never shown from the cut.
		if o.Offset > at {
			sb.Write(line[at:o.Offset])
		}
		sb.WriteString("«" + o.Shape + "»")
		at = end
	}
	if at < hi {
		sb.Write(line[at:hi])
	}
	if hi < len(line) {
		sb.WriteString("…")
	}
	return fp.Context(sb.String(), "")
}
