package known

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"keyguard/internal/core"
)

// Text git keeps about a change, rather than in a file (STEAL P0-13): the message of a commit
// and its author's name and email, the annotation of a tag, the name of a branch or a tag. A
// diff scan never sees any of it; betterleaks and gitleaks found a token in none of them,
// where TruffleHog and Titus found it in one or two. The commit-msg, reference-transaction
// and pre-push hooks and the mirror sweep all feed the same matcher through these functions.

// MessageFormat is the --format MatchMessages reads:
//
//	git log -z --format='%x01KG %H%n%an%n%ae%n%B' <revs> --
//
// One NUL-terminated record per commit: a marker line with the id, the author's name, the
// author's email, then the message. NUL is the one byte git refuses in a commit message.
const MessageFormat = "%x01KG %H%n%an%n%ae%n%B"

// RefFormat is the --format MatchRefs reads:
//
//	git for-each-ref --format='%(refname)%00%(contents)%00' [<patterns>]
const RefFormat = "%(refname)%00%(contents)%00"

// maxRecord bounds one record, so a hostile commit cannot make a hook allocate without limit.
// Past it the read fails loudly (bufio.ErrTooLong) and the caller says the text was not scanned.
const maxRecord = 64 << 20

// TextHit is a learned secret in the text git keeps about a change. It carries a shape and a
// context made of shapes, never the value.
type TextHit struct {
	Commit  string // the commit the text belongs to; "" for a ref name or a tag
	Ref     string // the ref, for a ref name or a tag annotation
	Field   string // commit message | author name | author email | ref name | tag annotation | ref contents
	Line    int    // 1-based, within the field
	Context string // the line around it with every learned secret replaced by its shape
	core.KnownMatch
}

// MatchText finds learned secrets in one piece of text and reports each with its field, its
// line within the text and a context made of shapes.
func MatchText(m core.KnownMatcher, field, commit, ref string, text []byte, fn func(TextHit)) {
	if m == nil || len(text) == 0 {
		return
	}
	ms := m.Match(text)
	for i, km := range ms {
		if km.Offset < 0 || km.Offset > len(text) {
			continue
		}
		ls := bytes.LastIndexByte(text[:km.Offset], '\n') + 1
		le := len(text)
		if j := bytes.IndexByte(text[km.Offset:], '\n'); j >= 0 {
			le = km.Offset + j
		}
		// The matches on this line, relative to it, for the context.
		var rel []core.KnownMatch
		at := 0
		for j, o := range ms {
			if o.Offset >= ls && o.Offset < le {
				if j == i {
					at = len(rel)
				}
				o.Offset -= ls
				rel = append(rel, o)
			}
		}
		fn(TextHit{
			Commit: commit, Ref: ref, Field: field,
			Line:       1 + bytes.Count(text[:ls], []byte{'\n'}),
			Context:    lineContext(text[ls:le], rel, at),
			KnownMatch: km,
		})
	}
}

// MatchMessages reads the output of git log with MessageFormat and reports every learned
// secret in a commit's message or its author's name or email. A record it cannot place is
// still searched, as part of the message of the last commit it saw.
func MatchMessages(m core.KnownMatcher, r io.Reader, fn func(TextHit)) error {
	sc := nulScanner(r)
	commit := ""
	for sc.Scan() {
		rec := sc.Bytes()
		if len(rec) == 0 {
			continue
		}
		parts := [][]byte{rec}
		fields := []string{"commit message"}
		if rest, ok := bytes.CutPrefix(rec, []byte("\x01KG ")); ok {
			head, tail, _ := bytes.Cut(rest, []byte{'\n'})
			commit = strings.TrimSpace(string(head))
			name, tail, ok1 := bytes.Cut(tail, []byte{'\n'})
			email, body, ok2 := bytes.Cut(tail, []byte{'\n'})
			if ok1 && ok2 {
				parts = [][]byte{name, email, body}
				fields = []string{"author name", "author email", "commit message"}
			} else {
				parts = [][]byte{tail}
			}
		}
		for i, p := range parts {
			MatchText(m, fields[min(i, len(fields)-1)], commit, "", p, fn)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("known: reading commit messages: %w", err)
	}
	return nil
}

// MatchRefs reads the output of git for-each-ref with RefFormat and reports every learned
// secret in a ref's name or in the text it holds: a tag's annotation, a branch tip's message.
func MatchRefs(m core.KnownMatcher, r io.Reader, fn func(TextHit)) error {
	sc := nulScanner(r)
	ref := ""
	for n := 0; sc.Scan(); n++ {
		tok := sc.Bytes()
		if n%2 == 0 { // for-each-ref ends each record with a newline, which opens the next token
			ref = strings.TrimPrefix(string(tok), "\n")
			MatchText(m, "ref name", "", ref, []byte(ref), fn)
			continue
		}
		field := "ref contents"
		if strings.HasPrefix(ref, "refs/tags/") {
			field = "tag annotation"
		}
		MatchText(m, field, "", ref, tok, fn)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("known: reading refs: %w", err)
	}
	return nil
}

func nulScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxRecord)
	sc.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, 0); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	return sc
}
