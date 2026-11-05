package hooks

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"keyguard/internal/core"
)

var line4 = regexp.MustCompile(`\(commit message\)\s+4\s`)

// plant is a learned key built at run time with a short public prefix (so the shape never
// shows ten characters of it) and the characters a ref name may hold.
func plant() string { return fakeGitHub() }

// wants checks that a block message names each text and none of the planted keys.
func wants(t *testing.T, what string, r result, keys []string, texts ...string) {
	t.Helper()
	for _, w := range texts {
		if !strings.Contains(r.err, w) {
			t.Errorf("%s: output lacks %q:\n%s", what, w, r.err)
		}
	}
	assertNoLeak(t, what+" stderr", r.err, keys...)
	assertNoLeak(t, what+" stdout", r.out, keys...)
}

// The commit-msg hook, through git's real hook wrapper (STEAL P0-13).
func TestCommitMsgBlocksALearnedKeyInTheMessage(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	base := e.commitFile(repo, "a.txt", "one\n", "init")
	key := plant()
	e.setKnown(map[string]string{"GITHUB_TOKEN": key})

	r := e.git(repo, "commit", "--allow-empty", "-m", "deploy with "+key)
	if r.code == 0 {
		t.Fatalf("a message holding a learned key went through:\n%s", r)
	}
	wants(t, "-m", r, []string{key}, "commit message blocked", "(commit message)", "learned key GITHUB_TOKEN", "ghp_…", "keyguard allow kg")

	// A later paragraph and the line it is on.
	r = e.git(repo, "commit", "--allow-empty", "-m", "subject", "-m", "body line\nsecond "+key)
	wants(t, "second -m", r, []string{key}, "commit message blocked")
	if r.code == 0 {
		t.Error("a key in the body went through")
	}
	if !line4.MatchString(r.err) {
		t.Errorf("the key is on line 4 of the message:\n%s", r.err)
	}

	// -F reads a file.
	msg := filepath.Join(e.root, "msg.txt")
	if err := os.WriteFile(msg, []byte("subject\n\n"+key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = e.git(repo, "commit", "--allow-empty", "-F", msg)
	if r.code == 0 {
		t.Error("a message file holding a key went through")
	}
	wants(t, "-F", r, []string{key}, "(commit message)")

	if head := e.must(repo, "rev-parse", "HEAD"); head != base {
		t.Errorf("HEAD moved to %s despite the block", head)
	}
	// The same world lets a clean message through.
	if r := e.git(repo, "commit", "--allow-empty", "-m", "a message with no key in it"); r.code != 0 {
		t.Errorf("a clean message was refused:\n%s", r)
	}
}

// --no-verify skips commit-msg, as it skips pre-commit. The reference-transaction hook is
// what catches the message then: it reads the messages and authors of the commits a ref is
// about to take.
func TestNoVerifyCannotCarryAKeyInAMessage(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	base := e.commitFile(repo, "a.txt", "one\n", "init")
	key := plant()
	e.setKnown(map[string]string{"GITHUB_TOKEN": key})

	r := e.git(repo, "commit", "--no-verify", "--allow-empty", "-m", "oops "+key)
	if r.code == 0 {
		t.Fatalf("--no-verify carried a key in a message:\n%s", r)
	}
	wants(t, "--no-verify", r, []string{key}, "ref update blocked", "(commit message)", "learned key GITHUB_TOKEN", "COMMIT")
	if head := e.must(repo, "rev-parse", "HEAD"); head != base {
		t.Errorf("HEAD moved to %s despite the abort", head)
	}

	// The author's name and email travel with the commit.
	r = e.git(repo, "-c", "user.name="+key, "commit", "--allow-empty", "-m", "by a key")
	if r.code == 0 {
		t.Fatalf("a key as the author's name went through:\n%s", r)
	}
	wants(t, "author", r, []string{key}, "(author name)")
	r = e.git(repo, "-c", "user.email="+key+"@example.invalid", "commit", "--allow-empty", "-m", "by a key")
	if r.code == 0 {
		t.Fatalf("a key in the author's email went through:\n%s", r)
	}
	wants(t, "email", r, []string{key}, "(author email)")

	// Amend, and a message made with plumbing, take the same way in.
	tree := e.must(repo, "write-tree")
	commit := e.must(repo, "commit-tree", tree, "-p", base, "-m", "plumbing "+key)
	if r := e.git(repo, "update-ref", "refs/heads/side", commit); r.code == 0 {
		t.Errorf("update-ref took a commit whose message holds a key")
	}
	if r := e.git(repo, "commit", "--amend", "--no-verify", "-m", "amended "+key); r.code == 0 {
		t.Errorf("an amend put the key in the message")
	}
}

// `git commit -v` shows the staged diff in the editor, below a scissors line git itself
// cuts off. Removing a leaked key from a file shows the key in that diff, and that commit
// must not be refused for it.
func TestCommitMsgIgnoresTheDiffTheEditorShows(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	key := plant()
	e.quietCommit(repo, "cfg.txt", "keep\ntoken="+key+"\n", "oops: a key")
	e.setKnown(map[string]string{"GITHUB_TOKEN": key})

	e.write(repo, "cfg.txt", "keep\n")
	e.must(repo, "add", "cfg.txt")
	// An editor that puts a subject above the template, which is all `git commit -v` needs.
	e.extra["GIT_EDITOR"] = `sh -c 'printf "remove the key\n" | cat - "$1" > "$1.new" && mv "$1.new" "$1"' --`
	r := e.git(repo, "commit", "-v")
	if r.code != 0 {
		t.Fatalf("removing a key was refused because the editor showed the diff:\n%s", r)
	}
	delete(e.extra, "GIT_EDITOR")
	// The comment character is the user's to choose, and the scissors line follows it.
	e.quietCommit(repo, "cfg.txt", "keep\ntoken="+key+"\n", "oops again")
	e.write(repo, "cfg.txt", "keep\n")
	e.must(repo, "add", "cfg.txt")
	e.extra["GIT_EDITOR"] = `sh -c 'printf "remove the key again\n" | cat - "$1" > "$1.new" && mv "$1.new" "$1"' --`
	r = e.git(repo, "-c", "core.commentChar=;", "commit", "-v")
	if r.code != 0 {
		t.Fatalf("removing a key was refused with core.commentChar=;:\n%s", r)
	}
	delete(e.extra, "GIT_EDITOR")
	// The scissors line is not a loophole: a message that happens to use the words, without
	// the line git writes under it, is still read.
	msg := filepath.Join(e.root, "m.txt")
	if err := os.WriteFile(msg, []byte("subject\n# ------------------------ >8 ------------------------\n"+key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := e.git(repo, "commit", "--allow-empty", "-F", msg); r.code == 0 {
		t.Errorf("a key after a scissors-looking line went through:\n%s", r)
	}
}

func TestRefTxBlocksKeysInTagsAndBranchNames(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	repo := e.initRepo("r")
	base := e.commitFile(repo, "a.txt", "one\n", "init")
	key := plant()
	e.setKnown(map[string]string{"GITHUB_TOKEN": key})

	for _, c := range []struct {
		what string
		args []string
		want string
	}{
		{"annotated tag message", []string{"tag", "-a", "v1", "-m", "release " + key}, "(tag annotation)"},
		{"lightweight tag name", []string{"tag", key}, "(ref name)"},
		{"branch name", []string{"branch", "feature/" + key}, "(ref name)"},
		{"checkout -b", []string{"checkout", "-b", key}, "(ref name)"},
		{"switch -c", []string{"switch", "-c", "x-" + key}, "(ref name)"},
		{"update-ref", []string{"update-ref", "refs/heads/" + key, base}, "(ref name)"},
	} {
		r := e.git(repo, c.args...)
		if r.code == 0 {
			t.Errorf("%s: git %s went through", c.what, c.args[0])
			continue
		}
		wants(t, c.what, r, []string{key}, "ref update blocked", c.want, "learned key GITHUB_TOKEN")
	}
	if tags := e.must(repo, "tag", "--list"); tags != "" {
		t.Errorf("a tag was created despite the block: %q", tags)
	}
	if br := e.must(repo, "branch", "--list", "--format=%(refname:short)"); br != "main" {
		t.Errorf("a branch was created despite the block: %q", br)
	}
	// Names and annotations with no key in them are not touched.
	for _, args := range [][]string{
		{"tag", "-a", "v2", "-m", "release 2"}, {"tag", "light"}, {"branch", "feature/login"}, {"checkout", "-q", "-b", "topic"},
	} {
		if r := e.git(repo, args...); r.code != 0 {
			t.Errorf("git %v was refused:\n%s", args, r)
		}
	}
}

func TestPrePushBlocksKeysInMessagesTagsAndRefNames(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	remote := e.initBare("origin.git")
	repo := e.initRepo("r")
	e.must(repo, "remote", "add", "origin", remote)
	e.quietCommit(repo, "a.txt", "1\n", "c1")
	e.mustQuiet(repo, "push", "-q", "-u", "origin", "main")
	key := plant()
	e.setKnown(map[string]string{"GITHUB_TOKEN": key})

	// A commit made with every hook off, a tag annotated with a key, a lightweight tag and a
	// branch named for one: none got past a hook on its way in, all meet pre-push on the way out.
	e.quietCommit(repo, "b.txt", "2\n", "message with "+key)
	r := e.git(repo, "push", "origin", "main")
	if r.code == 0 {
		t.Fatalf("a push carrying a key in a message went through:\n%s", r)
	}
	wants(t, "message", r, []string{key}, "push blocked", "(commit message)", "learned key GITHUB_TOKEN")
	if refs := e.must(remote, "for-each-ref", "--format=%(refname)"); strings.Contains(refs, "tags") {
		t.Errorf("remote refs after a refused push: %s", refs)
	}

	e.mustQuiet(repo, "reset", "-q", "--hard", "HEAD~1")
	e.quietCommit(repo, "c.txt", "3\n", "clean")
	e.mustQuiet(repo, "tag", "-a", "v1", "-m", "release "+key)
	r = e.git(repo, "push", "origin", "refs/tags/v1")
	if r.code == 0 {
		t.Fatalf("a push of a tag annotated with a key went through:\n%s", r)
	}
	wants(t, "annotation", r, []string{key}, "push blocked", "(tag annotation)")

	r = e.git(repo, "push", "origin", "HEAD:refs/heads/feature-"+key)
	if r.code == 0 {
		t.Fatalf("a push to a branch named for a key went through:\n%s", r)
	}
	wants(t, "branch", r, []string{key}, "push blocked", "(ref name)")

	// A tag that is named for a key but was made with the hooks off.
	e.mustQuiet(repo, "tag", "tag-"+key)
	r = e.git(repo, "push", "origin", "refs/tags/tag-"+key)
	if r.code == 0 {
		t.Fatalf("a push of a tag named for a key went through:\n%s", r)
	}
	wants(t, "tag name", r, []string{key}, "(ref name)")

	// And the clean push goes.
	e.mustQuiet(repo, "tag", "-d", "v1")
	e.mustQuiet(repo, "tag", "-d", "tag-"+key)
	if r := e.git(repo, "push", "origin", "main"); r.code != 0 {
		t.Errorf("a clean push was refused:\n%s", r)
	}
}

// History that arrives by clone, fetch or pull already exists elsewhere; its messages, tags
// and branch names are no more refused than its diffs are.
func TestMessagesTagsAndBranchesThatArriveByFetchAreNotRefused(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	key := plant()
	src := e.initRepo("src")
	e.quietCommit(src, "a.txt", "1\n", "message with "+key)
	e.mustQuiet(src, "tag", "-a", "v1", "-m", "annotated with "+key)
	e.mustQuiet(src, "branch", "branch-"+key)
	e.mustQuiet(src, "tag", "tag-"+key)
	e.setKnown(map[string]string{"GITHUB_TOKEN": key})

	probe := e.initRepo("probe")
	if e.git(probe, "commit", "--allow-empty", "-m", key).code == 0 {
		t.Fatal("control failed: the hooks are not active in this world")
	}
	dst := filepath.Join(e.root, "dst")
	for name, args := range map[string][]string{
		"clone":          {"clone", "-q", src, dst},
		"clone --bare":   {"clone", "-q", "--bare", src, filepath.Join(e.root, "bare.git")},
		"clone --mirror": {"clone", "-q", "--mirror", src, filepath.Join(e.root, "mirror.git")},
	} {
		if r := e.git(e.root, args...); r.code != 0 {
			t.Errorf("%s was refused:\n%s", name, r)
		}
	}
	e.quietCommit(src, "b.txt", "2\n", "another "+key)
	e.mustQuiet(src, "tag", "-a", "v2", "-m", "second "+key)
	if r := e.git(dst, "fetch", "--tags", "origin"); r.code != 0 {
		t.Errorf("fetch was refused:\n%s", r)
	}
	if r := e.git(dst, "pull", "--ff-only"); r.code != 0 {
		t.Errorf("pull was refused:\n%s", r)
	}
}

// The hook fails open: a message file it cannot read, or no store at all, never stops a commit.
func TestCommitMsgFailsOpenAndSaysSo(t *testing.T) {
	key := plant()
	var errb bytes.Buffer
	d := Deps{Known: newSubMatcher([]string{"K=" + key}), Stderr: &errb, FP: testKeyring}
	if code := CommitMsg(context.Background(), d, []string{filepath.Join(t.TempDir(), "missing")}); code != 0 {
		t.Errorf("an unreadable message blocked: %d", code)
	}
	if !strings.Contains(errb.String(), "could not read the commit message") {
		t.Errorf("no warning: %q", errb.String())
	}
	errb.Reset()
	if code := CommitMsg(context.Background(), d, nil); code != 0 || errb.Len() != 0 {
		t.Errorf("no argument: code %d, stderr %q", code, errb.String())
	}
	// No learned store: nothing to match, nothing printed.
	file := filepath.Join(t.TempDir(), "msg")
	if err := os.WriteFile(file, []byte("msg "+key), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := CommitMsg(context.Background(), Deps{Stderr: &errb}, []string{file}); code != 0 {
		t.Errorf("without a store a message blocked: %d", code)
	}
	// A relative path is read from Deps.Dir.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "msg"), []byte("msg "+key), 0o600); err != nil {
		t.Fatal(err)
	}
	d.Dir = dir
	if code := CommitMsg(context.Background(), d, []string{"msg"}); code != 1 {
		t.Errorf("a relative message path was not read from Dir: code %d", code)
	}
	assertNoLeak(t, "stderr", errb.String(), key)
}

// Every hit the message hooks make is a description in words, never the text itself.
func TestTextHitsNameThePlaceNotTheText(t *testing.T) {
	key := plant()
	var errb bytes.Buffer
	var recorded []core.Hit
	d := Deps{
		Known: newSubMatcher([]string{"K=" + key}), Stderr: &errb, FP: testKeyring,
		Record: func(layer string, hits []core.Hit) { recorded = append(recorded, hits...) },
	}
	file := filepath.Join(t.TempDir(), "msg")
	if err := os.WriteFile(file, []byte("a\nb "+key+" c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := CommitMsg(context.Background(), d, []string{file}); code != 1 {
		t.Fatalf("code %d", code)
	}
	if len(recorded) != 1 {
		t.Fatalf("recorded %d hits", len(recorded))
	}
	h := recorded[0]
	if h.Loc.Path != "(commit message)" || h.Loc.Line != 2 || h.Loc.Kind != "staged" || h.Engine != "known" || h.FP == "" {
		t.Errorf("hit: %+v", h)
	}
	if strings.Contains(h.Context, key[:10]) || !strings.Contains(h.Context, "«") {
		t.Errorf("context shows the key or no shape: %q", h.Context)
	}
	assertNoLeak(t, "stderr", errb.String(), key)
}

// A ref name that holds a key is not repeated anywhere. The hits the hook records (they reach
// the journal of blocks) do not carry the ref they were found under, and the report does not
// print it.
func TestRefTxNeverRepeatsARefNameThatHoldsAKey(t *testing.T) {
	e := newTenv(t)
	e.activate()
	repo := e.initRepo("r")
	key := plant()
	base := e.quietCommit(repo, "a.txt", "a\n", "base")
	sha := e.dangling(repo, base, "k.txt", key+"\n", "c")
	var recorded []core.Hit
	var stderr strings.Builder
	d := Deps{
		Dir: repo, Stderr: &stderr, Known: newSubMatcher([]string{"K=" + key}), FP: testKeyring,
		Record: func(layer string, hits []core.Hit) { recorded = append(recorded, hits...) },
	}
	in := fmt.Sprintf("%s %s refs/heads/%s\n", zeroOID, sha, key)
	if code := RefTx(context.Background(), d, []string{"prepared"}, strings.NewReader(in)); code != 1 {
		t.Fatalf("code %d:\n%s", code, stderr.String())
	}
	if len(recorded) < 2 {
		t.Fatalf("expected the ref name and the key in the diff, recorded %d hits", len(recorded))
	}
	for _, h := range recorded {
		if h.Loc.Ref != "" {
			t.Errorf("a hit carries the ref name: %+v", h.Loc)
		}
		assertNoLeak(t, "recorded hit", fmt.Sprintf("%+v", h), key)
	}
	assertNoLeak(t, "stderr", stderr.String(), key)
}
