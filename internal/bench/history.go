package bench

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"
)

// history writes a git fast-import stream. fast-import is real git, and a single process
// builds hundreds of commits with exact author/committer times, so the SHAs are repeatable
// per seed (commit ids depend only on tree, parents, author, committer and message).
type history struct {
	buf   bytes.Buffer
	marks int
	t     time.Time
	r     *rand.Rand
}

type branch struct {
	ref   string
	files map[string]string
	tip   int // mark of the newest commit, 0 before the first
}

type change struct {
	path    string
	content string
	del     bool
	from    string // when set, the file is renamed from this path to path before content is written
}

var authors = []struct{ name, email string }{
	{"Ada Bench", "ada@bench.invalid"},
	{"Lin Bench", "lin@bench.invalid"},
	{"Sam Bench", "sam@bench.invalid"},
}

func newHistory(r *rand.Rand) *history {
	return &history{t: time.Date(2024, 1, 8, 9, 0, 0, 0, time.UTC), r: r}
}

func (h *history) newBranch(ref string, from *branch) *branch {
	b := &branch{ref: ref, files: map[string]string{}}
	if from != nil {
		for k, v := range from.files {
			b.files[k] = v
		}
	}
	return b
}

func (h *history) data(s string) {
	fmt.Fprintf(&h.buf, "data %d\n%s\n", len(s), s)
}

func modeFor(path string) string {
	if strings.HasSuffix(path, ".sh") {
		return "100755"
	}
	return "100644"
}

// commit appends one commit to b. When b has no tip yet, parent (a mark, or 0) names the
// commit the branch starts from. merge, if non-zero, adds a second parent.
func (h *history) commit(b *branch, msg string, ch []change, parent, merge int) int {
	h.marks++
	mark := h.marks
	h.t = h.t.Add(time.Duration(17+h.r.IntN(80)) * time.Minute)
	a := authors[mark%len(authors)]
	stamp := fmt.Sprintf("%d +0000", h.t.Unix())
	fmt.Fprintf(&h.buf, "commit %s\nmark :%d\nauthor %s <%s> %s\ncommitter %s <%s> %s\n", b.ref, mark, a.name, a.email, stamp, a.name, a.email, stamp)
	h.data(msg)
	if b.tip == 0 && parent != 0 {
		fmt.Fprintf(&h.buf, "from :%d\n", parent)
	}
	if merge != 0 {
		fmt.Fprintf(&h.buf, "merge :%d\n", merge)
	}
	for _, c := range ch {
		if c.del {
			fmt.Fprintf(&h.buf, "D %s\n", c.path)
			delete(b.files, c.path)
			continue
		}
		if c.from != "" {
			fmt.Fprintf(&h.buf, "R %s %s\n", c.from, c.path)
			delete(b.files, c.from)
		}
		fmt.Fprintf(&h.buf, "M %s inline %s\n", modeFor(c.path), c.path)
		h.data(c.content)
		b.files[c.path] = c.content
	}
	h.buf.WriteString("\n")
	b.tip = mark
	return mark
}

// tag writes an annotated tag object pointing at a commit mark.
func (h *history) tag(name string, mark int, msg string) {
	a := authors[0]
	fmt.Fprintf(&h.buf, "tag %s\nfrom :%d\ntagger %s <%s> %d +0000\n", name, mark, a.name, a.email, h.t.Unix())
	h.data(msg) // the LF data writes is the only one a tag command takes
}
