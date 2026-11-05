package hooks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
)

// --no-verify skips pre-commit and pre-push, but not the reference-transaction hook: that
// is the whole reason the hook exists.
func TestRefTxBlocksNoVerifyCommitOfLearnedKey(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	base := e.commitFile(repo, "a.txt", "one\n", "init")
	key := fakeGitHub()
	e.setKnown(map[string]string{"GITHUB_TOKEN": key})

	e.write(repo, "cfg/settings.txt", "a=1\ntoken="+key+"\n")
	e.must(repo, "add", "cfg/settings.txt")
	r := e.git(repo, "commit", "--no-verify", "-m", "oops")
	if r.code == 0 {
		t.Fatalf("--no-verify commit of a learned key went through:\n%s", r)
	}
	for _, want := range []string{"reference-transaction hook", "ref update blocked", "COMMIT", "cfg/settings.txt", "learned key GITHUB_TOKEN", "ghp_…"} {
		if !strings.Contains(r.err, want) {
			t.Errorf("stderr lacks %q:\n%s", want, r.err)
		}
	}
	assertNoLeak(t, "stderr", r.err, key)
	if head := e.must(repo, "rev-parse", "HEAD"); head != base {
		t.Errorf("HEAD moved to %s despite the abort", head)
	}

	// Same through amend, plumbing, tags and branch creation: every way a commit with the
	// key can end up on a branch or tag.
	e.must(repo, "reset", "-q")
	e.must(repo, "add", "cfg/settings.txt")
	tree := e.must(repo, "write-tree")
	commit := e.must(repo, "commit-tree", tree, "-p", base, "-m", "plumbing")
	for _, args := range [][]string{
		{"update-ref", "refs/heads/side", commit},
		{"branch", "other", commit},
		{"tag", "t1", commit},
		{"tag", "-a", "t2", "-m", "annotated", commit},
	} {
		if r := e.git(repo, args...); r.code == 0 {
			t.Errorf("git %v recorded a commit holding a learned key", args)
		}
	}
	e.must(repo, "reset", "-q")
	if r := e.git(repo, "commit", "--amend", "--no-verify", "--allow-empty", "-m", "amended"); r.code != 0 {
		t.Errorf("an amend with nothing new should pass:\n%s", r)
	}
	e.must(repo, "add", "cfg/settings.txt")
	if r := e.git(repo, "commit", "--amend", "--no-verify", "-m", "amended with key"); r.code == 0 {
		t.Errorf("--amend --no-verify of a learned key went through")
	}
}

func TestRefTxBlocksTheFirstCommitOfARepo(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("fresh")
	key := fakeGitHub()
	e.setKnown(map[string]string{"K": key})
	e.write(repo, "k.txt", key+"\n")
	e.must(repo, "add", "k.txt")
	r := e.git(repo, "commit", "--no-verify", "-m", "first")
	if r.code == 0 || !strings.Contains(r.err, "ref update blocked") {
		t.Fatalf("first commit with a learned key was not blocked:\n%s", r)
	}
	if e.git(repo, "rev-parse", "--verify", "-q", "HEAD").code == 0 {
		t.Errorf("a commit exists")
	}
}

// A key the matcher has never seen is the engines' job at push time.
func TestUnknownKeyPassesRefTxAndPrePushBlocksIt(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	remote := e.initBare("remote.git")
	repo := e.initRepo("r")
	e.must(repo, "remote", "add", "origin", remote)
	e.commitFile(repo, "a.txt", "one\n", "init")
	if r := e.git(repo, "push", "-q", "-u", "origin", "main"); r.code != 0 {
		t.Fatalf("clean first push blocked:\n%s", r)
	}
	before := e.must(remote, "rev-parse", "main")

	key := fakeGitHub() // not registered anywhere
	e.write(repo, "oops.txt", "token = \""+key+"\"\n")
	e.must(repo, "add", "oops.txt")
	if r := e.git(repo, "commit", "--no-verify", "-q", "-m", "oops"); r.code != 0 {
		t.Fatalf("reftx must not block a key it does not know:\n%s", r)
	}

	r := e.git(repo, "push", "origin", "main")
	if r.code == 0 {
		t.Fatalf("push of an unknown key went through:\n%s", r)
	}
	for _, want := range []string{"push blocked", "oops.txt", "github-pat", "ghp_…", "COMMIT"} {
		if !strings.Contains(r.err, want) {
			t.Errorf("stderr lacks %q:\n%s", want, r.err)
		}
	}
	assertNoLeak(t, "stderr", r.err, key)
	if after := e.must(remote, "rev-parse", "main"); after != before {
		t.Errorf("remote moved to %s", after)
	}

	// Rewriting the commit away lets the next push through.
	e.must(repo, "reset", "-q", "--hard", "HEAD~1")
	e.commitFile(repo, "b.txt", "two\n", "clean")
	if r := e.git(repo, "push", "-q", "origin", "main"); r.code != 0 {
		t.Errorf("clean push after the fix was blocked:\n%s", r)
	}
}

// The matrix the spec calls out: history that arrives from elsewhere, and git housekeeping,
// must never be refused, even when the history holds a key keyguard has learned.
func TestRefTxNeverBlocksIncomingHistoryOrHousekeeping(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	key1, key2 := fakeGitHub(), fakeGitHub()

	src := e.initRepo("src")
	e.quietCommit(src, "a.txt", "one\n", "c1")
	leak1 := e.quietCommit(src, "leak1.txt", "t="+key1+"\n", "c2 holds a key")
	e.mustQuiet(src, "tag", "v1")
	e.mustQuiet(src, "branch", "feature")
	e.setKnown(map[string]string{"ONE": key1, "TWO": key2})

	// Control: in this same world, authoring a commit with a learned key is refused. Without
	// it a pass below could just mean the hook was never running.
	probe := e.initRepo("probe")
	e.write(probe, "k.txt", key1+"\n")
	e.must(probe, "add", "k.txt")
	if e.git(probe, "commit", "--no-verify", "-m", "x").code == 0 {
		t.Fatal("control failed: reftx is not active in this test world")
	}

	step := func(name string, dir string, args ...string) {
		t.Helper()
		if r := e.git(dir, args...); r.code != 0 {
			t.Errorf("%s: git %v was refused:\n%s", name, args, r)
		}
	}

	dst := filepath.Join(e.root, "dst")
	step("clone", e.root, "clone", "-q", src, dst)
	step("clone --bare", e.root, "clone", "-q", "--bare", src, filepath.Join(e.root, "bare.git"))
	step("clone --mirror", e.root, "clone", "-q", "--mirror", src, filepath.Join(e.root, "mirror.git"))
	step("clone --depth 1", e.root, "clone", "-q", "--depth", "1", "file://"+src, filepath.Join(e.root, "shallow"))

	// fetch: a new commit with another learned key, and a new tag, arrive together.
	e.quietCommit(src, "leak2.txt", "t="+key2+"\n", "c3")
	e.mustQuiet(src, "tag", "v2")
	step("fetch", dst, "fetch", "origin")
	step("fetch --tags", dst, "fetch", "--tags", "origin")

	// pull, fast-forward
	e.quietCommit(src, "more.txt", "m\n", "c4")
	step("pull --ff-only", dst, "pull", "--ff-only")

	// pull, merge: local work and upstream work diverge
	e.commitFile(dst, "local1.txt", "l1\n", "local 1")
	e.quietCommit(src, "up5.txt", "t="+key2+"\n", "c5")
	step("pull (merge)", dst, "pull", "--no-rebase", "--no-edit")

	// pull --rebase
	e.commitFile(dst, "local2.txt", "l2\n", "local 2")
	e.quietCommit(src, "up6.txt", "u6\n", "c6")
	step("pull --rebase", dst, "pull", "--rebase")

	// A fetch straight into a local branch by URL leaves no remote-tracking ref to subtract:
	// only knowing the process is a fetch keeps this from being refused.
	e.quietCommit(src, "up7.txt", "t="+key1+"\n", "c7")
	step("fetch into a branch", dst, "fetch", src, "main:viaurl")

	// A merging pull by URL leaves no remote-tracking ref either; its merge step names
	// FETCH_HEAD, which is how the hook knows the other side is incoming.
	e.quietCommit(src, "up8.txt", "t="+key2+"\n", "c8")
	e.commitFile(dst, "local3.txt", "l3\n", "local 3")
	step("pull by URL (merge)", dst, "pull", "--no-rebase", "--no-edit", src, "main")

	// Everyday housekeeping on a clone full of learned keys.
	step("checkout -b", dst, "checkout", "-q", "-b", "topic")
	e.commitFile(dst, "topic.txt", "t\n", "topic work")
	step("rebase", dst, "rebase", "-q", "main")
	step("switch back", dst, "checkout", "-q", "main")
	step("merge --no-ff", dst, "merge", "-q", "--no-ff", "--no-edit", "topic")
	step("lightweight tag on an existing commit", dst, "tag", "lw", "HEAD~1")
	step("annotated tag on an existing commit", dst, "tag", "-a", "ann", "-m", "x", "HEAD~2")
	step("branch from history", dst, "branch", "old", "v1")
	step("branch -D", dst, "branch", "-D", "topic")
	step("tag -d", dst, "tag", "-d", "lw")
	step("branch to pick from", dst, "checkout", "-q", "-b", "pickme", "main~2")
	pick := e.commitFile(dst, "picked.txt", "p\n", "to pick")
	step("back to main", dst, "checkout", "-q", "main")
	step("cherry-pick of a clean commit", dst, "cherry-pick", "-x", pick)
	step("reset --hard", dst, "reset", "-q", "--hard", "HEAD~1")

	// stash: a learned key in the working tree is not committed by stashing it
	e.write(dst, "a.txt", "one\nstashed="+key1+"\n")
	step("stash", dst, "stash")
	step("stash drop", dst, "stash", "drop")

	// And the world is still armed after all of that.
	e.write(dst, "bad.txt", key2+"\n")
	e.must(dst, "add", "bad.txt")
	if e.git(dst, "commit", "--no-verify", "-m", "bad").code == 0 {
		t.Errorf("reftx stopped working in the clone")
	}
	_ = leak1
}

// A commit already on a branch, tag or remote was judged when it got there. Judging it
// again would make `git tag`, `git branch` or a local merge fail in any repo whose old
// unpushed history holds a key; a commit no ref has taken yet is still judged.
func TestRefTxJudgesOnlyCommitsNoRefHasTakenYet(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	key := fakeGitHub()
	base := e.quietCommit(repo, "a.txt", "1\n", "base")
	e.mustQuiet(repo, "checkout", "-q", "-b", "old")
	oldLeak := e.quietCommit(repo, "k.txt", "t="+key+"\n", "old unpushed history holds a key")
	e.mustQuiet(repo, "checkout", "-q", "main")
	e.quietCommit(repo, "b.txt", "2\n", "main moves on")
	e.setKnown(map[string]string{"K": key})

	for _, args := range [][]string{
		{"tag", "v1", oldLeak},
		{"tag", "-a", "v2", "-m", "x", oldLeak},
		{"branch", "copy", oldLeak},
		{"merge", "--no-edit", "old"}, // a non-fast-forward merge of a local branch
		{"checkout", "-q", "-b", "next"},
	} {
		if r := e.git(repo, args...); r.code != 0 {
			t.Errorf("git %v re-judged history that is already on a ref:\n%s", args, r)
		}
	}

	// A commit that no branch, tag or remote has taken is judged when one does, even if it
	// sits on a detached HEAD, which is not one of them.
	e.must(repo, "checkout", "-q", "--detach", base)
	e.write(repo, "d.txt", "k="+key+"\n")
	e.must(repo, "add", "d.txt")
	if r := e.git(repo, "commit", "--no-verify", "-q", "-m", "on a detached HEAD"); r.code != 0 {
		t.Fatalf("a commit on a detached HEAD updates no branch and is not judged yet:\n%s", r)
	}
	for _, args := range [][]string{
		{"branch", "rescued"},
		{"tag", "rescued-tag"},
		{"switch", "-c", "rescued2"},
	} {
		if r := e.git(repo, args...); r.code == 0 {
			t.Errorf("git %v took a detached commit holding a learned key", args)
		}
	}
	dangling := e.dangling(repo, base, "z.txt", key+"\n", "never on a ref")
	if r := e.git(repo, "branch", "fromplumbing", dangling); r.code == 0 {
		t.Errorf("a plumbing commit holding a learned key became a branch")
	}
}

// Bare repositories hold history that arrived by clone, fetch or push; keyguard's own
// mirrors are fed leaked keys on purpose. Neither may be refused.
func TestRefTxSkipsBareReposAndMirrorCaches(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	key := fakeGitHub()
	src := e.initRepo("src")
	e.quietCommit(src, "a.txt", "one\n", "c1")
	leak := e.quietCommit(src, "leak.txt", "t="+key+"\n", "c2")
	e.setKnown(map[string]string{"K": key})

	caches := []string{
		filepath.Join(e.kgHome, "cache", "mirrors", "github.com", "o", "r.git"),             // $KEYGUARD_HOME
		filepath.Join(e.home, ".keyguard", "cache", "mirrors", "github.com", "o", "r2.git"), // the real root, under this world's HOME
		filepath.Join(e.root, "elsewhere", "plain.git"),                                     // a bare repo outside any cache
	}
	for _, c := range caches {
		if err := os.MkdirAll(filepath.Dir(c), 0o755); err != nil {
			t.Fatal(err)
		}
		if r := e.git(e.root, "clone", "-q", "--mirror", src, c); r.code != 0 {
			t.Fatalf("mirror clone into %s:\n%s", c, r)
		}
		for _, args := range [][]string{
			{"fetch", "-q", "origin"},
			{"update-ref", "refs/heads/zz", leak},
			{"tag", "zt", leak},
			{"branch", "bb", leak},
		} {
			if r := e.git(c, args...); r.code != 0 {
				t.Errorf("%s: git %v refused:\n%s", c, args, r)
			}
		}
	}

	// A push into a bare repository is a receive, not an authoring.
	recv := e.initBare("recv.git")
	other := e.initRepo("other")
	e.quietCommit(other, "k.txt", key+"\n", "has key")
	e.mustQuiet(other, "remote", "add", "origin", recv)
	if r := e.git(other, append(noHooks, "push", "-q", "origin", "main")...); r.code != 0 {
		t.Errorf("push into a bare repo was refused:\n%s", r)
	}
}

// Skipping bare repositories must not switch the hook off for the "bare repo plus linked
// worktrees" layout: commits are authored in the worktree, which is not bare.
func TestRefTxStillGuardsWorktrees(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	src := e.initRepo("src")
	e.quietCommit(src, "a.txt", "1\n", "c1")
	bare := filepath.Join(e.root, "bare.git")
	e.must(e.root, "clone", "-q", "--bare", src, bare)
	wt := filepath.Join(e.root, "wt")
	e.must(bare, "worktree", "add", "-q", wt, "main")
	plain := filepath.Join(e.root, "wt2")
	e.must(src, "worktree", "add", "-q", "-b", "other", plain)

	key := fakeGitHub()
	e.setKnown(map[string]string{"K": key})
	for name, dir := range map[string]string{"worktree of a bare repo": wt, "linked worktree": plain} {
		e.write(dir, "k.txt", key+"\n")
		e.must(dir, "add", "k.txt")
		if r := e.git(dir, "commit", "--no-verify", "-m", "x"); r.code == 0 {
			t.Errorf("%s: a learned key was committed past the hook", name)
		}
	}
}

// The cache-root rule on its own, without the bare-repo rule doing the work: a non-bare
// repository under a cache root is skipped, the same repository elsewhere is not.
func TestRefTxSkipsAnythingUnderACacheRoot(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	key := fakeGitHub()
	e.setKnown(map[string]string{"K": key})
	for name, dir := range map[string]string{
		"keyguard home": filepath.Join(e.kgHome, "cache", "mirrors", "w"),
		"real root":     filepath.Join(e.home, ".keyguard", "cache", "mirrors", "w"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		e.must(dir, "init", "-q", "-b", "main")
		e.write(dir, "k.txt", key+"\n")
		e.must(dir, "add", "k.txt")
		if r := e.git(dir, "commit", "--no-verify", "-m", "in "+name); r.code != 0 {
			t.Errorf("%s: commit under the cache was refused:\n%s", name, r)
		}
	}
	// Same thing outside: refused.
	out := e.initRepo("outside")
	e.write(out, "k.txt", key+"\n")
	e.must(out, "add", "k.txt")
	if e.git(out, "commit", "--no-verify", "-m", "x").code == 0 {
		t.Errorf("the repo outside the cache was not protected")
	}
}

// A merge whose conflict resolution adds a key: the key sits only in the combined (--cc)
// diff, on a line that is new in the merge and in neither parent.
func TestRefTxFindsAKeyInAMergeResolution(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	e.commitFile(repo, "f.txt", "a\nb\nc\n", "base")
	e.must(repo, "checkout", "-q", "-b", "side")
	e.commitFile(repo, "f.txt", "a\nSIDE\nc\n", "side")
	e.must(repo, "checkout", "-q", "main")
	e.commitFile(repo, "f.txt", "a\nMAIN\nc\n", "main")
	if e.git(repo, "merge", "side").code == 0 {
		t.Fatal("expected a conflict")
	}
	key := fakeGitHub()
	e.setKnown(map[string]string{"K": key})
	e.write(repo, "f.txt", "a\nsecret = "+key+"\nc\n")
	e.must(repo, "add", "f.txt")
	r := e.git(repo, "commit", "--no-verify", "-m", "merge")
	if r.code == 0 {
		t.Fatalf("a key introduced by a merge resolution went through:\n%s", r)
	}
	if !strings.Contains(r.err, "f.txt") || !strings.Contains(r.err, "learned key K") {
		t.Errorf("message does not locate it:\n%s", r.err)
	}
	assertNoLeak(t, "stderr", r.err, key)
	// Line 2 of f.txt, from the combined hunk header.
	if !tableHasRow(r.err, "f.txt", 2) {
		t.Errorf("expected f.txt line 2 in:\n%s", r.err)
	}
}

// tableHasRow reports whether the block message's table has a row for file at line.
func tableHasRow(msg, file string, line int) bool {
	for _, l := range strings.Split(msg, "\n") {
		f := strings.Fields(l)
		for i, w := range f {
			if w == file && i+1 < len(f) && f[i+1] == fmt.Sprint(line) {
				return true
			}
		}
	}
	return false
}

// Clone puts the tags and refs/remotes/* in one transaction. At "prepared" the remote refs
// do not exist yet, so the hook must subtract their incoming tips itself.
func TestRefTxSubtractsIncomingRemoteTips(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	key := fakeGitHub()
	// History no ref points at yet, like the commits a clone is still writing refs for.
	c1 := e.dangling(repo, "", "a.txt", "a\n", "c1")
	c2 := e.dangling(repo, c1, "k.txt", key+"\n", "c2")
	tip := e.dangling(repo, c2, "b.txt", "b\n", "c3")
	e.setKnown(map[string]string{"K": key})

	clone := fmt.Sprintf("%s %s refs/remotes/origin/main\n%s %s refs/tags/v1\n", zeroOID, tip, zeroOID, tip)
	if r := e.hook(repo, NameRefTx, clone, "prepared"); r.code != 0 {
		t.Errorf("a clone-shaped transaction was refused:\n%s", r)
	}
	tagOnly := fmt.Sprintf("%s %s refs/tags/v1\n", zeroOID, tip)
	if r := e.hook(repo, NameRefTx, tagOnly, "prepared"); r.code == 0 {
		t.Errorf("without the remote tip in the transaction the tag must be scanned")
	}
}

func TestRefTxIgnoresWhatIsNotABranchOrTagUpdate(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	key := fakeGitHub()
	e.setKnown(map[string]string{"K": key})
	base := e.quietCommit(repo, "a.txt", "a\n", "base")
	leak := e.dangling(repo, base, "k.txt", key+"\n", "has key")
	other := e.quietCommit(repo, "o.txt", "o\n", "other")

	armed := fmt.Sprintf("%s %s refs/heads/x\n", zeroOID, leak)
	if r := e.hook(repo, NameRefTx, armed, "prepared"); r.code == 0 {
		t.Fatalf("control: the leaking branch update should be refused")
	}
	for name, stdin := range map[string]string{
		"stash":              fmt.Sprintf("%s %s refs/stash\n", zeroOID, leak),
		"remote-tracking":    fmt.Sprintf("%s %s refs/remotes/origin/x\n", zeroOID, leak),
		"notes":              fmt.Sprintf("%s %s refs/notes/commits\n", zeroOID, leak),
		"HEAD":               fmt.Sprintf("%s %s HEAD\n", zeroOID, leak),
		"ORIG_HEAD":          fmt.Sprintf("%s %s ORIG_HEAD\n", zeroOID, leak),
		"symbolic HEAD":      fmt.Sprintf("%s ref:refs/heads/x HEAD\n", zeroOID),
		"symbolic branch":    fmt.Sprintf("%s ref:refs/heads/main refs/heads/alias\n", zeroOID),
		"delete":             fmt.Sprintf("%s %s refs/heads/x\n", leak, zeroOID),
		"zero to zero":       fmt.Sprintf("%s %s refs/heads/x\n", zeroOID, zeroOID),
		"garbage":            "not even a ref update\n",
		"ancestor move back": fmt.Sprintf("%s %s refs/heads/x\n", leak, other),
		"empty":              "",
	} {
		if r := e.hook(repo, NameRefTx, stdin, "prepared"); r.code != 0 {
			t.Errorf("%s: refused:\n%s", name, r)
		}
	}
	for _, state := range []string{"preparing", "committed", "aborted", "", "bogus"} {
		args := []string{}
		if state != "" {
			args = append(args, state)
		}
		if r := e.hook(repo, NameRefTx, armed, args...); r.code != 0 {
			t.Errorf("state %q: refused:\n%s", state, r)
		}
	}
}

func TestRefTxCapsTheScanAt2000Commits(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	key := fakeGitHub()
	e.setKnown(map[string]string{"K": key})

	// n commits, each adding a file; the commit at keyAt (1-based, oldest first) holds the key.
	build := func(name string, n, keyAt int) (repo, tip string) {
		repo = e.initRepo(name)
		var b bytes.Buffer
		for i := 1; i <= n; i++ {
			content := fmt.Sprintf("file %d\n", i)
			if i == keyAt {
				content = "k=" + key + "\n"
			}
			fmt.Fprintf(&b, "commit refs/internal/history\ncommitter T <t@e.com> %d +0000\ndata 2\nc\nM 100644 inline f%d.txt\ndata %d\n%s\n", 1700000000+i, i, len(content), content)
		}
		if r := e.run(repo, b.String(), "git", append(append([]string{}, noHooks...), "fast-import", "--quiet")...); r.code != 0 {
			t.Fatalf("fast-import: %s", r)
		}
		return repo, e.must(repo, "rev-parse", "refs/internal/history")
	}
	update := func(repo, tip string) result {
		return e.hook(repo, NameRefTx, fmt.Sprintf("%s %s refs/heads/main\n", zeroOID, tip), "prepared")
	}

	// 2000 commits: all scanned, nothing to say.
	repo, tip := build("exact", 2000, 1)
	if r := update(repo, tip); r.code == 0 || strings.Contains(r.err, "scanned the newest") {
		t.Errorf("2000 commits with the key in the oldest should be fully scanned and refused:\n%s", r)
	}

	// 2001: the oldest falls off. Exit 0, and the cap is announced.
	repo, tip = build("over", 2001, 1)
	r := update(repo, tip)
	if r.code != 0 || !strings.Contains(r.err, "2000") || !strings.Contains(r.err, "scanned the newest") {
		t.Errorf("2001 commits: want exit 0 and a note about the 2000 cap:\n%s", r)
	}

	// 2100 with the key in the newest: caught despite the cap.
	repo, tip = build("recent", 2100, 2100)
	if r := update(repo, tip); r.code == 0 {
		t.Errorf("a key in the newest commit must be found even when capped:\n%s", r)
	}
}

func TestRefTxFailsOpen(t *testing.T) {
	e := newTenv(t)
	e.activate()
	repo := e.initRepo("r")
	key := fakeGitHub()
	base := e.quietCommit(repo, "a.txt", "a\n", "base")
	sha := e.dangling(repo, base, "k.txt", key+"\n", "c")
	in := fmt.Sprintf("%s %s refs/heads/main\n", zeroOID, sha)
	var stderr strings.Builder
	run := func(d Deps, stdin string) int {
		stderr.Reset()
		d.Dir, d.Stderr = repo, &stderr
		return RefTx(context.Background(), d, []string{"prepared"}, strings.NewReader(stdin))
	}

	if code := run(Deps{Known: newSubMatcher([]string{"K=" + key})}, in); code != 1 {
		t.Fatalf("control: code %d, want 1\n%s", code, stderr.String())
	}
	if code := run(Deps{LoadKnown: func() (core.KnownMatcher, error) { return nil, errors.New("known.json is corrupt") }}, in); code != 0 || strings.Count(stderr.String(), "warning") != 1 {
		t.Errorf("unloadable store: code %d, stderr %q", code, stderr.String())
	}
	if code := run(Deps{Known: newSubMatcher([]string{"K=" + key})}, fmt.Sprintf("%s %s refs/heads/main\n", zeroOID, strings.Repeat("ab", 20))); code != 0 || strings.Count(stderr.String(), "warning") != 1 {
		t.Errorf("unknown object: code %d, stderr %q", code, stderr.String())
	}
	if code := run(Deps{}, in); code != 0 || stderr.Len() != 0 {
		t.Errorf("no matcher at all: code %d, stderr %q", code, stderr.String())
	}
	// A repo git cannot open at all.
	{
		stderr.Reset()
		d := Deps{Dir: filepath.Join(e.root, "not-a-repo"), Known: newSubMatcher([]string{"K=" + key}), Stderr: &stderr}
		if err := os.MkdirAll(d.Dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if code := RefTx(context.Background(), d, []string{"prepared"}, strings.NewReader(in)); code != 0 || strings.Count(stderr.String(), "warning") != 1 {
			t.Errorf("not a repo: code %d, stderr %q", code, stderr.String())
		}
	}
	// A panic in the injected matcher is caught by Run.
	{
		stderr.Reset()
		d := Deps{Dir: repo, Stderr: &stderr, Known: panicMatcher{}}
		if code := Run(context.Background(), NameRefTx, []string{"prepared"}, strings.NewReader(in), d); code != 0 || !strings.Contains(stderr.String(), "internal error") {
			t.Errorf("panic: code %d, stderr %q", code, stderr.String())
		}
	}
}

type panicMatcher struct{}

func (panicMatcher) Match([]byte) []core.KnownMatch { panic("matcher bug") }
func (panicMatcher) Len() int                       { return 1 }

// Exiting early must not cost a store load: committed/aborted calls happen on every ref
// update, and the store is the heavy part.
func TestRefTxDoesNotLoadTheStoreWhenThereIsNothingToScan(t *testing.T) {
	e := newTenv(t)
	e.activate()
	repo := e.initRepo("r")
	sha := e.quietCommit(repo, "a.txt", "a\n", "c")
	loads := 0
	d := Deps{Dir: repo, Stderr: &strings.Builder{}, LoadKnown: func() (core.KnownMatcher, error) { loads++; return newSubMatcher(nil), nil }}
	for _, c := range []struct {
		state, in string
	}{
		{"committed", fmt.Sprintf("%s %s refs/heads/main\n", zeroOID, sha)},
		{"preparing", fmt.Sprintf("%s %s refs/heads/main\n", zeroOID, sha)},
		{"prepared", fmt.Sprintf("%s %s refs/stash\n", zeroOID, sha)},
		{"prepared", fmt.Sprintf("%s %s refs/heads/main\n", sha, zeroOID)},
	} {
		RefTx(context.Background(), d, []string{c.state}, strings.NewReader(c.in))
	}
	if loads != 0 {
		t.Errorf("store loaded %d times for no-op invocations", loads)
	}
}

func TestIsFetchCommand(t *testing.T) {
	for argv, want := range map[string]bool{
		"git fetch origin": true,
		"/opt/homebrew/opt/git/libexec/git-core/git fetch --update-head-ok": true,
		"git -C /r fetch":                       true,
		"git -c core.x=y clone u d":             true,
		"git clone --bare a b":                  true,
		"git-receive-pack /srv/r.git":           true,
		"/usr/lib/git-core/git-receive-pack /r": true,
		"git commit -m fetch":                   false,
		"git -c user.name=fetch commit":         false,
		"git commit":                            false,
		"git merge FETCH_HEAD":                  true,
		"git -C /r merge --no-edit FETCH_HEAD":  true,
		"git merge feature":                     false,
		"git rebase -i":                         false,
		"sh -c fetch":                           false,
		"":                                      false,
		"git":                                   false,
	} {
		if got := isFetchCommand(strings.Fields(argv)); got != want {
			t.Errorf("isFetchCommand(%q) = %v, want %v", argv, got, want)
		}
	}
}
