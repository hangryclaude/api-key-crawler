package engines

import (
	"context"
	"regexp"
	"strings"
	"time"

	"keyguard/internal/core"
)

// refNamer finds a ref that contains each hit's commit. The engines do not say which ref a
// finding was on, and a commit only reachable through refs/pull/* is a different problem
// from one on main (deleting the branch does not remove it), so the ref is worth a batched
// `git name-rev` per scan. Failure leaves Ref empty: it is context, not evidence.
type refNamer struct {
	ctx    context.Context
	gitDir string
	refs   map[string]string // loaded on first use
	cache  map[string]string // commit -> full ref name ("" = none found)
}

func newRefNamer(ctx context.Context, gitDir string) *refNamer {
	return &refNamer{ctx: ctx, gitDir: gitDir, cache: map[string]string{}}
}

// namePasses are tried in order and a commit keeps the first name it gets, so a branch beats
// a tag beats a pull ref. name-rev alone would prefer the tag, which says less about where
// the commit lives.
var namePasses = [][]string{{"refs/heads/*", "refs/remotes/*"}, {"refs/tags/*"}, {"refs/*"}}

// refSuffix strips name-rev's distance annotations: "main~3", "tags/v1^0", "pull/1/head~2^2".
var refSuffix = regexp.MustCompile(`([~^][0-9]*)+$`)

const nameRevBatch = 500

func (n *refNamer) fill(hits []core.Hit) {
	var todo []string
	seen := map[string]bool{}
	for _, h := range hits {
		c := h.Loc.Commit
		if _, done := n.cache[c]; c == "" || done || seen[c] {
			continue
		}
		seen[c] = true
		todo = append(todo, c)
	}
	if len(todo) > 0 {
		n.resolve(todo)
	}
	for i := range hits {
		if r := n.cache[hits[i].Loc.Commit]; r != "" {
			hits[i].Loc.Ref = r
		}
	}
}

func (n *refNamer) resolve(commits []string) {
	ctx, cancel := context.WithTimeout(n.ctx, 60*time.Second)
	defer cancel()
	if n.refs == nil {
		refs, err := liveRefs(ctx, n.gitDir)
		if err != nil {
			refs = map[string]string{}
		}
		n.refs = refs
	}
	remaining := commits
	for _, pass := range namePasses {
		var next []string
		for len(remaining) > 0 {
			batch := remaining[:min(nameRevBatch, len(remaining))]
			remaining = remaining[len(batch):]
			args := []string{"name-rev", "--name-only"}
			for _, p := range pass {
				args = append(args, "--refs="+p)
			}
			out, err := gitRepo(ctx, n.gitDir, append(append(args, "--"), batch...)...)
			lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
			for i, c := range batch {
				if err == nil && i < len(lines) {
					if r := n.fullRef(refSuffix.ReplaceAllString(strings.TrimSpace(lines[i]), "")); r != "" {
						n.cache[c] = r
						continue
					}
				}
				next = append(next, c)
			}
		}
		remaining = next
	}
	for _, c := range remaining {
		n.cache[c] = ""
	}
}

// fullRef undoes name-rev's shortening ("main" for refs/heads/main, "tags/v1" for
// refs/tags/v1) by checking which spelling is a real ref.
func (n *refNamer) fullRef(short string) string {
	if short == "" || short == "undefined" {
		return ""
	}
	for _, cand := range []string{"refs/" + short, "refs/heads/" + short, short} {
		if _, ok := n.refs[cand]; ok {
			return cand
		}
	}
	return ""
}
