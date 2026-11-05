package engines

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"keyguard/internal/core"
)

// gitOut runs git and returns stdout; a failure carries the scrubbed stderr.
func gitOut(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := gitCmd(ctx, dir, nil, args...)
	var stderr tailBuf
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("engines: git %s: %v; stderr: %s", subcommand(args), err, stderr.text())
	}
	return out, nil
}

// gitRepo runs git against a git dir without depending on the working directory.
func gitRepo(ctx context.Context, gitDir string, args ...string) ([]byte, error) {
	return gitOut(ctx, gitDir, append([]string{"--git-dir=" + gitDir}, args...)...)
}

func subcommand(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return "?"
}

// gitDirOf resolves a repository path (bare repo, worktree root, or a .git dir) to its git
// dir. Engines are pointed at the git dir rather than the worktree because betterleaks and
// gitleaks read .gitleaksignore and .gitleaks.toml from the scanned path: a repo must not be
// able to switch off its own scan.
func gitDirOf(ctx context.Context, repo string) (string, error) {
	if _, err := os.Stat(repo); err != nil {
		return "", fmt.Errorf("engines: %w", err)
	}
	out, err := gitOut(ctx, repo, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// gitScan is a repository and the rev-list arguments describing what to scan in it.
type gitScan struct {
	dir  string   // absolute git dir
	args []string // rev-list arguments; empty when the range selects nothing
}

// openGit resolves repo and r. A range that selects no commits yields a scan with no args,
// which every caller treats as "nothing to do" without starting an engine (titus in
// particular falls back to scanning the files of a repo without history).
func (b *base) openGit(ctx context.Context, repo string, r core.Range) (gitScan, error) {
	abs, err := filepath.Abs(repo)
	if err != nil {
		return gitScan{}, err
	}
	dir, err := gitDirOf(ctx, abs)
	if err != nil {
		return gitScan{}, err
	}
	args, err := b.revArgs(ctx, dir, r)
	if err != nil || len(args) == 0 {
		return gitScan{dir: dir}, err
	}
	out, err := gitRepo(ctx, dir, append(append([]string{"rev-list", "-n", "1"}, args...), "--")...)
	if err != nil {
		return gitScan{}, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return gitScan{dir: dir}, nil
	}
	return gitScan{dir: dir, args: args}, nil
}

// validRev admits what a caller can legitimately put in Range.Revs and nothing git would take
// for an option with side effects (--output=<file> would make `git log` write a file).
func validRev(s string) error {
	if s == "" || strings.ContainsAny(s, " \t\r\n\x00") {
		return fmt.Errorf("engines: bad rev %q", s)
	}
	if !strings.HasPrefix(s, "-") {
		return nil
	}
	name, _, _ := strings.Cut(s, "=")
	switch name {
	case "--all", "--not", "--branches", "--tags", "--remotes", "--glob", "--exclude":
		return nil
	}
	return fmt.Errorf("engines: rev option %q not allowed", name)
}

// revArgs turns a Range into rev-list arguments. Old tips from Since come first as "^tip":
// a "--not" inside Revs only flips what follows it, so they stay negative. Tips git no longer
// has (gc after a force-push) are dropped, which only ever widens the scan.
func (b *base) revArgs(ctx context.Context, gitDir string, r core.Range) ([]string, error) {
	if !r.All && len(r.Revs) == 0 && len(r.Since) == 0 {
		return nil, errors.New("engines: empty range: set All, Revs or Since")
	}
	for _, v := range r.Revs {
		if err := validRev(v); err != nil {
			return nil, err
		}
	}
	var args []string
	if len(r.Since) > 0 {
		var tips []string
		for _, ref := range slices.Sorted(maps.Keys(r.Since)) {
			tips = append(tips, r.Since[ref])
		}
		have, err := existingCommits(ctx, gitDir, tips)
		if err != nil {
			return nil, err
		}
		if gone := distinctValid(tips) - len(have); gone > 0 {
			b.note("%d recorded tip(s) are no longer in the repository (gc after a force-push?), so the scan covers more than the range asked for", gone)
		}
		for _, oid := range have {
			args = append(args, "^"+oid)
		}
	}
	if r.All {
		args = append(args, "--all")
	}
	args = append(args, r.Revs...)
	if !r.All && len(r.Revs) == 0 {
		// Since alone: scan the refs it names, from their old tips to wherever they are now.
		live, err := liveRefs(ctx, gitDir)
		if err != nil {
			return nil, err
		}
		var named bool
		for _, ref := range slices.Sorted(maps.Keys(r.Since)) {
			if _, ok := live[ref]; ok {
				args = append(args, ref)
				named = true
			}
		}
		if !named {
			return nil, nil
		}
	}
	return args, nil
}

// distinctValid counts the tips existingCommits would look up.
func distinctValid(tips []string) int {
	seen := map[string]bool{}
	for _, t := range tips {
		if validRev(t) == nil && !strings.HasPrefix(t, "-") {
			seen[t] = true
		}
	}
	return len(seen)
}

// existingCommits resolves tips to full commit ids, dropping duplicates, malformed entries
// and anything the repo does not have.
func existingCommits(ctx context.Context, gitDir string, tips []string) ([]string, error) {
	var in bytes.Buffer
	for _, t := range tips {
		if validRev(t) != nil || strings.HasPrefix(t, "-") {
			continue
		}
		in.WriteString(t + "^{commit}\n") // an annotated tag id would otherwise not count as a commit
	}
	if in.Len() == 0 {
		return nil, nil
	}
	cmd := gitCmd(ctx, gitDir, nil, "--git-dir="+gitDir, "cat-file", "--batch-check")
	cmd.Stdin = &in
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("engines: git cat-file: %w", err)
	}
	seen := map[string]bool{}
	var have []string
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 3 && f[1] == "commit" && !seen[f[0]] {
			seen[f[0]] = true
			have = append(have, f[0])
		}
	}
	return have, nil
}

func liveRefs(ctx context.Context, gitDir string) (map[string]string, error) {
	out, err := gitRepo(ctx, gitDir, "for-each-ref", "--format=%(refname) %(objectname)")
	if err != nil {
		return nil, err
	}
	refs := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if name, oid, ok := strings.Cut(l, " "); ok {
			refs[name] = oid
		}
	}
	return refs, nil
}

// newCommits is the set of commits a range selects, with the structure trufflehog needs to
// scan it without rescanning history: the range's heads and, per head, an excluded commit
// to start after.
type newCommits struct {
	set     map[string]struct{}
	heads   []string // commits no other commit in the set descends from
	parents map[string][]string
}

func listNewCommits(ctx context.Context, gitDir string, args []string) (*newCommits, error) {
	out, err := gitRepo(ctx, gitDir, append(append([]string{"rev-list", "--parents"}, args...), "--")...)
	if err != nil {
		return nil, err
	}
	nc := &newCommits{set: map[string]struct{}{}, parents: map[string][]string{}}
	isParent := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		nc.set[f[0]] = struct{}{}
		nc.parents[f[0]] = f[1:]
		for _, p := range f[1:] {
			isParent[p] = true
		}
	}
	for c := range nc.set {
		if !isParent[c] {
			nc.heads = append(nc.heads, c)
		}
	}
	slices.Sort(nc.heads)
	return nc, nil
}

// since walks from head through the new commits and returns the first excluded parent it
// meets, "" when all of head's history is new. Any one is a safe place to start after:
// everything reachable from an excluded commit is excluded too, so `head ^since` can only be
// wider than the range, never narrower.
func (nc *newCommits) since(head string) string {
	seen := map[string]bool{head: true}
	queue := []string{head}
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		for _, p := range nc.parents[c] {
			if _, in := nc.set[p]; !in {
				return p
			}
			if !seen[p] {
				seen[p] = true
				queue = append(queue, p)
			}
		}
	}
	return ""
}
