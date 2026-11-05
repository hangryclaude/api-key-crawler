package hooks

import (
	"bufio"
	"bytes"
	"io"
	"strconv"
	"strings"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// diffMatch is one learned secret found on a line a change adds.
type diffMatch struct {
	Commit string // "" for the staged diff
	Path   string
	Line   int
	Ctx    string // the line with the secret replaced by its shape
	Entr   float64
	KM     core.KnownMatch
}

const (
	// A run of added lines is matched when it ends. A run longer than chunk (one giant
	// minified line, say) is matched in pieces that overlap by overlap bytes, so a value
	// straddling the cut is still whole in one piece.
	chunk   = 4 << 20
	overlap = 4 << 10
)

var newline = []byte{'\n'}

// diffScanner reads `git diff` / `git log -p --cc` output with the commit marker line and
// feeds the learned-secret matcher the text of each run of added lines (prefix stripped,
// joined with newlines), so multi-line values such as the head of a private key match.
//
// It tracks hunk state instead of trusting line shapes: inside a hunk every line starts
// with '+', '-' or ' ', so an added line "++ x" (diff shows "+++ x") is content, never a
// file header. Headers are only believed before the first hunk of a file.
type diffScanner struct {
	m     core.KnownMatcher
	found func(diffMatch)
	onAdd func(path string, line int) // optional: told where every added line sits

	commit string
	path   string
	inHunk bool
	cols   int // prefix width: 1, or one per parent in a --cc merge hunk
	cur    int // new-file line number of the next result line

	run     []byte
	runLine int // new-file line of the first byte of run

	frag []byte
	seen map[string]struct{}
}

// scanAdded streams r through the matcher. maxCommits > 0 stops at the first commit
// beyond that many and reports capped, leaving the caller to stop git.
func scanAdded(r io.Reader, m core.KnownMatcher, maxCommits int, found func(diffMatch)) (commits int, capped bool, err error) {
	s := &diffScanner{m: m, found: found, seen: map[string]struct{}{}}
	return s.drive(r, maxCommits)
}

// scanPositions reports the file and new-file line of every added line, matching nothing.
func scanPositions(r io.Reader, at func(path string, line int)) error {
	s := &diffScanner{onAdd: at}
	_, _, err := s.drive(r, 0)
	return err
}

func (s *diffScanner) drive(r io.Reader, maxCommits int) (commits int, capped bool, err error) {
	br := bufio.NewReaderSize(r, 256<<10)
	for {
		line, rerr := s.readLine(br)
		if len(line) > 0 || rerr == nil {
			if len(line) > 0 && line[0] == 0x01 {
				s.flush(true)
				commits++
				if maxCommits > 0 && commits > maxCommits {
					return maxCommits, true, nil
				}
				s.commit = strings.TrimPrefix(string(line[1:]), "KG ")
				s.path, s.inHunk = "", false
			} else {
				s.line(line)
			}
		}
		if rerr != nil {
			s.flush(true)
			if rerr == io.EOF {
				return commits, false, nil
			}
			return commits, false, rerr
		}
	}
}

// readLine returns one line without its newline, however long. The slice is only valid
// until the next call.
func (s *diffScanner) readLine(br *bufio.Reader) ([]byte, error) {
	s.frag = s.frag[:0]
	for {
		part, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			s.frag = append(s.frag, part...)
			continue
		}
		if len(s.frag) > 0 {
			s.frag = append(s.frag, part...)
			part = s.frag
		}
		return bytes.TrimSuffix(part, newline), err
	}
}

func (s *diffScanner) line(l []byte) {
	switch {
	case bytes.HasPrefix(l, []byte("@@")):
		s.flush(true)
		s.inHunk = false
		if cols, start, ok := parseHunk(l); ok {
			s.cols, s.cur, s.inHunk = cols, start, true
		}
	case s.inHunk && s.content(l):
	case bytes.HasPrefix(l, []byte("diff ")):
		s.flush(true)
		s.path, s.inHunk = "", false
	case !s.inHunk && bytes.HasPrefix(l, []byte("+++ ")):
		s.path = parseNewPath(string(l[4:]))
	default:
		// index/mode/rename lines, the blank line after a commit marker, "\ No newline".
		if s.inHunk && !bytes.HasPrefix(l, []byte("\\")) {
			s.flush(true)
			s.inHunk = false
		}
	}
}

// content handles one hunk line and reports whether it was one.
func (s *diffScanner) content(l []byte) bool {
	if len(l) < s.cols {
		return false
	}
	removed, allPlus := false, true
	for _, c := range l[:s.cols] {
		switch c {
		case '+':
		case '-':
			removed, allPlus = true, false
		case ' ':
			allPlus = false
		default:
			return false
		}
	}
	switch {
	case removed:
		// Gone from the result: neither a new line nor a break between added ones.
	case allPlus:
		if s.onAdd != nil {
			s.onAdd(s.path, s.cur)
		}
		if s.m != nil {
			if len(s.run) == 0 {
				s.runLine = s.cur
			}
			s.run = append(append(s.run, l[s.cols:]...), '\n')
		}
		s.cur++
		s.flush(false)
	default:
		// Present in a parent already (combined diffs): history that is checked on its own.
		s.flush(true)
		s.cur++
	}
	return true
}

// flush matches the pending run. force=false only acts once the run is big enough to cut.
func (s *diffScanner) flush(force bool) {
	if len(s.run) == 0 || (!force && len(s.run) < chunk) {
		return
	}
	s.match()
	if force {
		s.run = s.run[:0]
		return
	}
	cut := len(s.run) - overlap
	s.runLine += bytes.Count(s.run[:cut], newline)
	s.run = append(s.run[:0], s.run[cut:]...)
}

func (s *diffScanner) match() {
	if s.m == nil {
		return
	}
	for _, km := range s.m.Match(s.run) {
		if km.Offset < 0 || km.Offset > len(s.run) {
			continue
		}
		end := min(km.Offset+km.Len, len(s.run))
		line := s.runLine + bytes.Count(s.run[:km.Offset], newline)
		key := s.commit + "|" + s.path + "|" + strconv.Itoa(line) + "|" + km.FP
		if _, dup := s.seen[key]; dup {
			continue
		}
		s.seen[key] = struct{}{}
		path := s.path
		if path == "" {
			path = "(unknown file)"
		}
		s.found(diffMatch{
			Commit: s.commit,
			Path:   path,
			Line:   line,
			Ctx:    matchContext(s.run, km.Offset, end, km.Shape),
			Entr:   fp.Entropy(string(s.run[km.Offset:end])),
			KM:     km,
		})
	}
}

// matchContext is the line around a match with the matched bytes replaced by the shape,
// never the bytes themselves. Only a window of the line is considered: a minified bundle
// can be megabytes on one line.
func matchContext(run []byte, off, end int, shape string) string {
	ls := bytes.LastIndexByte(run[:off], '\n') + 1
	le := bytes.IndexByte(run[end:], '\n')
	if le < 0 {
		le = len(run)
	} else {
		le += end
	}
	ls, le = max(ls, off-100), min(le, end+100)
	// Cutting a window can slice a multibyte rune; ToValidUTF8 repairs the edges.
	before := strings.ToValidUTF8(string(run[ls:off]), "")
	after := strings.ToValidUTF8(string(run[end:le]), "")
	return fp.Context(before+"«"+shape+"»"+after, "")
}

// parseHunk reads "@@ -a,b +c,d @@" (or the "@@@" combined form) and returns the number
// of prefix columns (one per parent) and the first new-file line.
func parseHunk(l []byte) (cols, start int, ok bool) {
	n := 0
	for n < len(l) && l[n] == '@' {
		n++
	}
	i := bytes.Index(l[n:], []byte(" +"))
	if n < 2 || i < 0 {
		return 0, 0, false
	}
	j := n + i + 2
	k := j
	for k < len(l) && l[k] >= '0' && l[k] <= '9' {
		k++
	}
	if k == j {
		return 0, 0, false
	}
	v, err := strconv.Atoi(string(l[j:k]))
	if err != nil {
		return 0, 0, false
	}
	return n - 1, v, true
}

// parseNewPath reads the name after "+++ ". git quotes names with odd bytes in C style and
// adds a trailing tab when a name has spaces.
func parseNewPath(s string) string {
	s = strings.TrimSuffix(s, "\t")
	if s == "/dev/null" {
		return ""
	}
	if strings.HasPrefix(s, `"`) {
		if u, err := strconv.Unquote(s); err == nil {
			s = u
		}
	}
	return strings.TrimPrefix(s, "b/")
}
