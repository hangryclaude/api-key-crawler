package mirror

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"keyguard/internal/core"
)

func TestPathLayoutMatchesBootstrap(t *testing.T) {
	m, err := New(Config{Root: filepath.Join(t.TempDir(), "mirrors")})
	if err != nil {
		t.Fatal(err)
	}
	r := m.cfg.Root
	for id, want := range map[string]string{
		"github.com/hangryclaude/headroom":                              "github.com/hangryclaude/headroom.git",
		"github.com/hangryclaude/headroom.wiki":                         "github.com/hangryclaude/headroom.wiki.git",
		"gist.github.com/hangryclaude/3f9a1c0de27b4658a1d2e3f4a5b6c7d8": "gist.github.com/hangryclaude/3f9a1c0de27b4658a1d2e3f4a5b6c7d8.git",
		"github.com/Loony-Labs-Video/congress-trading-investigation":    "github.com/Loony-Labs-Video/congress-trading-investigation.git",
		"github.com/hangryclaude/.github":                               "github.com/hangryclaude/.github.git",
	} {
		if got := m.Path(core.Source{ID: id}); got != filepath.Join(r, want) {
			t.Errorf("Path(%s) = %s, want %s", id, got, filepath.Join(r, want))
		}
	}
	for _, bad := range []string{
		"", "github.com", "github.com/a", "github.com/a/b/c", "github.com/../b", "github.com/a/..", "github.com/./b",
		"github.com/a/b c", "GitHub.com/a/b", "github/a/b", "github.com//b", "github.com/a/b\x00", "github.com/a/b\n",
		"../github.com/a/b", "/github.com/a/b", "github.com/a/b/", "github.com/a/-rf;", "github.com/a/$(x)",
	} {
		if p := m.Path(core.Source{ID: bad}); p != "" {
			t.Errorf("Path(%q) = %q, want none", bad, p)
		}
		if _, _, err := m.Sync(context.Background(), core.Source{ID: bad}); err == nil {
			t.Errorf("Sync(%q) accepted", bad)
		}
	}
	if _, err := New(Config{Root: "relative/dir"}); err == nil {
		t.Error("a relative root was accepted")
	}
}

func TestCloneThenNoOpFetch(t *testing.T) {
	e := newTenv(t, nil)
	s := e.src("hangryclaude", "headroom", "repo")

	first := e.sync(s)
	if !first.Cloned || len(first.Before) != 0 || !maps.Equal(first.After, e.tips()) || len(first.After) == 0 {
		t.Fatalf("clone result = %+v, upstream tips %v", first, e.tips())
	}
	dest := filepath.Join(e.root, "github.com", "hangryclaude", "headroom.git")
	if e.m.Path(s) != dest {
		t.Fatalf("Path = %s", e.m.Path(s))
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "config")); !strings.Contains(string(b), "mirror = true") || !strings.Contains(string(b), "bare = true") {
		t.Errorf("not a bare mirror clone:\n%s", b)
	}
	if left, _ := filepath.Glob(dest + ".partial"); len(left) != 0 {
		t.Errorf("partial left behind: %v", left)
	}

	second := e.sync(s)
	if second.Cloned || !maps.Equal(second.Before, second.After) || !maps.Equal(second.After, first.After) || len(second.Moved()) != 0 {
		t.Fatalf("no-op fetch = %+v", second)
	}

	tip := e.commit("README", "two\n", "second")
	third := e.sync(s)
	if !maps.Equal(third.Before, first.After) || third.After["refs/heads/main"] != tip || !slices.Equal(third.Moved(), []string{"refs/heads/main"}) {
		t.Fatalf("fetch after a push = %+v, want main moved to %s", third, tip)
	}

	// The core.Mirror entry point reports the same tips.
	b, a, err := e.m.Sync(context.Background(), s)
	if err != nil || !maps.Equal(b, a) || a["refs/heads/main"] != tip {
		t.Fatalf("Sync = %v %v %v", b, a, err)
	}
}

func TestMirrorFollowsBranchesTagsPullRefsDeletionsAndForcePushes(t *testing.T) {
	e := newTenv(t, nil)
	s := e.src("o", "n", "repo")
	e.sync(s)

	base := e.git("rev-parse", "HEAD")
	e.git("checkout", "-q", "-b", "feature")
	feat := e.commit("f.txt", "feature\n", "feature work")
	e.git("checkout", "-q", "main")
	e.git("tag", "-a", "v1", "-m", "release")
	e.git("tag", "light")
	e.git("update-ref", "refs/pull/1/head", feat)
	e.git("update-ref", "refs/pull/1/merge", base)
	r := e.sync(s)
	if !maps.Equal(r.After, e.tips()) {
		t.Fatalf("mirror %v\nupstream %v", r.After, e.tips())
	}
	for _, ref := range []string{"refs/heads/feature", "refs/tags/v1", "refs/tags/light", "refs/pull/1/head", "refs/pull/1/merge"} {
		if r.After[ref] == "" {
			t.Errorf("%s not mirrored", ref)
		}
	}
	if want := []string{"refs/heads/feature", "refs/pull/1/head", "refs/pull/1/merge", "refs/tags/light", "refs/tags/v1"}; !slices.Equal(r.Moved(), want) {
		t.Errorf("Moved = %v, want %v", r.Moved(), want)
	}

	// Deletions are pruned, tags included: the mirror must not keep refs GitHub dropped.
	e.git("branch", "-q", "-D", "feature")
	e.git("tag", "-d", "light")
	e.git("update-ref", "-d", "refs/pull/1/merge")
	r = e.sync(s)
	if !maps.Equal(r.After, e.tips()) {
		t.Fatalf("after deletions mirror %v\nupstream %v", r.After, e.tips())
	}
	for _, gone := range []string{"refs/heads/feature", "refs/tags/light", "refs/pull/1/merge"} {
		if _, ok := r.After[gone]; ok {
			t.Errorf("%s survived the prune", gone)
		}
	}
	if len(r.Moved()) != 0 {
		t.Errorf("deletions are not 'moved': %v", r.Moved())
	}

	// A history rewrite is a forced update; the mirror follows it and keeps the old objects.
	old := e.git("rev-parse", "main")
	e.git("reset", "-q", "--hard", "HEAD~0")
	e.git("commit", "-q", "--amend", "-m", "rewritten", "--allow-empty")
	r = e.sync(s)
	if r.Before["refs/heads/main"] != old || r.After["refs/heads/main"] != e.git("rev-parse", "main") || r.After["refs/heads/main"] == old {
		t.Fatalf("force push not followed: %+v", r)
	}
	dest := e.m.Path(s)
	if out := e.catFile(dest, old); out != "commit" {
		t.Errorf("the pre-rewrite commit is gone from the mirror (%q): a secret removed by a force push would be unscannable", out)
	}
}

// catFile asks the mirror what an object is.
func (e *tenv) catFile(gitDir, obj string) string {
	e.t.Helper()
	out, _, err := e.m.git(context.Background(), time.Minute, "", false, "--git-dir="+gitDir, "cat-file", "-t", obj)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func TestKeyguardHooksNeverRunInsideAMirror(t *testing.T) {
	e := newTenv(t, nil)
	e.useHooks()
	s := e.src("o", "n", "repo")

	// Control: the sandbox config really does fire the hook, so silence below means something.
	_, _ = rawGitCmd("clone", "--mirror", "--quiet", "file://"+e.up, filepath.Join(e.tmp, "control.git")).CombinedOutput()
	if b, _ := os.ReadFile(e.hookLog); !strings.Contains(string(b), "reference-transaction") {
		t.Fatalf("control clone did not trigger the reference-transaction hook; the test would prove nothing (log %q)", b)
	}
	if err := os.Remove(e.hookLog); err != nil {
		t.Fatal(err)
	}

	e.sync(s) // clone
	e.commit("a", "a\n", "more")
	e.git("tag", "-a", "v9", "-m", "x")
	r := e.sync(s) // fetch, with a new ref transaction in the mirror
	if r.After["refs/tags/v9"] == "" {
		t.Fatalf("fetch did not land: %+v", r)
	}
	if b, err := os.ReadFile(e.hookLog); err == nil {
		t.Fatalf("keyguard hooks ran inside the mirror:\n%s", b)
	}
}

func TestStalePartialIsReplacedAndAFailedCloneLeavesNothing(t *testing.T) {
	e := newTenv(t, nil)
	s := e.src("o", "n", "repo")
	dest := e.m.Path(s)
	if err := os.MkdirAll(dest+".partial/objects", 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, dest+".partial/leftover", "from a killed clone")
	r := e.sync(s)
	if !r.Cloned {
		t.Fatalf("result = %+v", r)
	}
	if _, err := os.Lstat(dest + ".partial"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale partial still there: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "leftover")); err == nil {
		t.Error("the mirror contains the stale partial's files")
	}

	bad := e.src("o", "gone", "repo")
	bad.CloneURL = "file://" + filepath.Join(e.tmp, "no-such-upstream")
	_, _, err := e.m.Sync(context.Background(), bad)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	for _, p := range []string{e.m.Path(bad), e.m.Path(bad) + ".partial"} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s exists after a failed clone", p)
		}
	}
}

func TestWikiThatIsNotThereIsAbsentNotAnError(t *testing.T) {
	e := newTenv(t, nil)
	wiki := e.src("o", "n.wiki", "wiki")
	wiki.CloneURL = "file://" + filepath.Join(e.tmp, "no-such-wiki")
	r, err := e.m.SyncResult(context.Background(), wiki)
	if err != nil || !r.Absent || r.Cloned || len(r.Before) != 0 || len(r.After) != 0 {
		t.Fatalf("absent wiki: err=%v result=%+v", err, r)
	}
	before, after, err := e.m.Sync(context.Background(), wiki)
	if err != nil || len(before) != 0 || len(after) != 0 {
		t.Fatalf("core.Mirror view of an absent wiki: %v %v %v", before, after, err)
	}
	if _, err := os.Lstat(e.m.Path(wiki)); err == nil {
		t.Error("a mirror directory was created for a wiki that does not exist")
	}

	// The same failure for a repo is an error, and a typed one.
	repo := wiki
	repo.ID, repo.Kind = "github.com/o/n", "repo"
	if _, err := e.m.SyncResult(context.Background(), repo); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repo err = %v, want ErrNotFound", err)
	}

	// A wiki that existed and then went away keeps its mirror and reports absent.
	live := e.src("o", "n.wiki", "wiki")
	first := e.sync(live)
	if first.Absent || len(first.After) == 0 {
		t.Fatalf("live wiki = %+v", first)
	}
	// The mirror fetches from the origin it recorded when it was cloned, so take that away.
	moved := e.up + ".moved"
	if err := os.Rename(e.up, moved); err != nil {
		t.Fatal(err)
	}
	gone := e.sync(live)
	if !gone.Absent || !maps.Equal(gone.Before, first.After) || !maps.Equal(gone.After, first.After) {
		t.Fatalf("vanished wiki = %+v", gone)
	}
}

func TestAMirrorGitDoesNotRecogniseIsMovedAsideAndRecloned(t *testing.T) {
	e := newTenv(t, nil)
	s := e.src("o", "n", "repo")
	dest := e.m.Path(s)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dest, "junk"), "not a repository")

	r := e.sync(s)
	if !r.Cloned || !maps.Equal(r.After, e.tips()) {
		t.Fatalf("result = %+v", r)
	}
	stale, _ := filepath.Glob(filepath.Join(e.root, ".stale", "github.com__o__n.git.*"))
	if len(stale) != 1 {
		t.Fatalf("the unusable directory should be kept under .stale, found %v", stale)
	}
	if b, err := os.ReadFile(filepath.Join(stale[0], "junk")); err != nil || string(b) != "not a repository" {
		t.Errorf("quarantined content changed: %q %v", b, err)
	}
}

func TestADamagedMirrorInsideAnotherRepositoryIsNotMistakenForThatRepository(t *testing.T) {
	e := newTenv(t, nil)
	// The cache root is itself a checkout. `git -C <mirror>` on a broken mirror would search
	// upward, find that checkout and fetch into it; --git-dir must refuse instead.
	if out, err := rawGitCmd("init", "-q", e.root).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if err := os.MkdirAll(e.m.Path(e.src("o", "n", "repo")), 0o700); err != nil {
		t.Fatal(err)
	}
	r := e.sync(e.src("o", "n", "repo"))
	if !r.Cloned || !maps.Equal(r.After, e.tips()) {
		t.Fatalf("a repository above the mirror hijacked the sync: %+v", r)
	}
	if out, _ := rawGitCmd("-C", e.root, "config", "--get", "remote.origin.url").Output(); len(out) != 0 {
		t.Fatalf("the enclosing repository was given a remote: %s", out)
	}
}

func TestATimedOutCloneKillsTheWholeProcessTree(t *testing.T) {
	e := newTenv(t, func(c *Config) { c.CloneTimeout = time.Second })
	s := e.src("o", "n", "repo")
	s.CloneURL = "file:///kg-block"
	start := time.Now()
	_, err := e.m.SyncResult(context.Background(), s)
	if !errors.Is(err, ErrTimeout) || time.Since(start) > 15*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
	b, rerr := os.ReadFile(e.pidFile)
	if rerr != nil {
		t.Fatalf("the blocking remote never started: %v", rerr)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	dead := false
	for range 40 {
		if syscall.Kill(pid, 0) != nil {
			dead = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !dead {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("pid %d, a grandchild of git, outlived the timeout", pid)
	}
	if _, err := os.Lstat(e.m.Path(s) + ".partial"); err == nil {
		t.Error("partial clone kept after a timeout")
	}
}

func TestCancellingTheContextKillsARunningCloneAndStaysInspectable(t *testing.T) {
	e := newTenv(t, nil)
	s := e.src("o", "n", "repo")
	s.CloneURL = "file:///kg-block"
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(400 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := e.m.SyncResult(ctx, s)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrTimeout) || time.Since(start) > 15*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
	if _, err := os.Lstat(e.m.Path(s) + ".partial"); err == nil {
		t.Error("partial clone kept after cancellation")
	}
}

func TestCancellingTheContextStopsAWaitingSync(t *testing.T) {
	e := newTenv(t, nil)
	s := e.src("o", "n", "repo")
	rel, _ := relPath(s.ID)
	release, err := e.m.lock(context.Background(), rel) // someone else is mid-clone
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = e.m.SyncResult(ctx, s)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
}

func TestConcurrentSyncsOfOneSourceCloneOnce(t *testing.T) {
	e := newTenv(t, nil)
	s := e.src("o", "n", "repo")
	other := e.src("o", "m", "repo")
	var wg sync.WaitGroup
	results := make([]Result, 8)
	errs := make([]error, 8)
	for i := range results {
		wg.Go(func() {
			src := s
			if i%4 == 3 {
				src = other
			}
			results[i], errs[i] = e.m.SyncResult(context.Background(), src)
		})
	}
	wg.Wait()
	cloned := map[string]int{}
	for i, r := range results {
		if errs[i] != nil {
			t.Fatalf("sync %d: %v", i, errs[i])
		}
		if !maps.Equal(r.After, e.tips()) {
			t.Errorf("sync %d saw %v", i, r.After)
		}
		if r.Cloned {
			if i%4 == 3 {
				cloned["m"]++
			} else {
				cloned["n"]++
			}
		}
	}
	if cloned["n"] != 1 || cloned["m"] != 1 {
		t.Errorf("clones per source = %v, want one each", cloned)
	}
}

func TestChildGitEnvironmentIsScrubbed(t *testing.T) {
	e := newTenv(t, nil)
	want := e.tips() // read before the environment turns hostile: tips() is git too
	t.Setenv("GIT_DIR", filepath.Join(e.tmp, "wrong-repo"))
	t.Setenv("GIT_WORK_TREE", e.tmp)
	t.Setenv("GIT_INDEX_FILE", filepath.Join(e.tmp, "index"))
	t.Setenv("GIT_TRACE", "1")
	t.Setenv("GIT_CURL_VERBOSE", "1")
	t.Setenv("GIT_TRACE_PACKET", "1")
	env := strings.Join(e.m.env(), "\n")
	for _, bad := range []string{"GIT_DIR=", "GIT_WORK_TREE=", "GIT_INDEX_FILE=", "GIT_TRACE", "GIT_CURL_VERBOSE"} {
		if strings.Contains(env, bad) {
			t.Errorf("child environment still has %s", bad)
		}
	}
	for _, want := range []string{"GIT_TERMINAL_PROMPT=0", "LC_ALL=C", "GIT_CONFIG_GLOBAL=" + e.plain} {
		if !strings.Contains(env, want) {
			t.Errorf("child environment lacks %s", want)
		}
	}
	// A hook-time GIT_DIR must not redirect the sync into another repository.
	r := e.sync(e.src("o", "n", "repo"))
	if !r.Cloned || !maps.Equal(r.After, want) {
		t.Fatalf("sync under a hostile environment = %+v", r)
	}
}

func TestMirrorDirectoriesArePrivate(t *testing.T) {
	e := newTenv(t, nil)
	s := e.src("o", "n", "repo")
	e.sync(s)
	for _, p := range []string{e.root, filepath.Dir(filepath.Dir(e.m.Path(s))), filepath.Dir(e.m.Path(s)), e.m.Path(s)} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: mode %v err %v, want 0700", p, fi.Mode().Perm(), err)
		}
	}
}

func TestTipsReadsAnExistingMirrorWithoutTheNetwork(t *testing.T) {
	e := newTenv(t, nil)
	s := e.src("o", "n", "repo")
	if _, err := e.m.Tips(context.Background(), s); err == nil {
		t.Error("Tips of a mirror that does not exist succeeded")
	}
	r := e.sync(s)
	e.commit("x", "x\n", "unfetched")
	tips, err := e.m.Tips(context.Background(), s)
	if err != nil || !maps.Equal(tips, r.After) {
		t.Fatalf("Tips = %v %v, want the mirror's own %v", tips, err, r.After)
	}
	if _, err := e.m.Tips(context.Background(), core.Source{ID: "nope"}); err == nil {
		t.Error("bad id accepted")
	}
}

func TestMovedListsNewAndChangedRefsOnly(t *testing.T) {
	before := map[string]string{"refs/heads/a": "1", "refs/heads/b": "2", "refs/heads/gone": "3"}
	after := map[string]string{"refs/heads/a": "1", "refs/heads/b": "9", "refs/heads/new": "4"}
	if got := Moved(before, after); !slices.Equal(got, []string{"refs/heads/b", "refs/heads/new"}) {
		t.Errorf("Moved = %v", got)
	}
	if got := Moved(nil, nil); len(got) != 0 {
		t.Errorf("Moved(nil, nil) = %v", got)
	}
}

func TestDiscardRefusesAnythingButItsOwnPartials(t *testing.T) {
	e := newTenv(t, nil)
	victim := filepath.Join(e.tmp, "precious")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(victim, "keep"), "x")
	for _, p := range []string{
		victim, e.root, filepath.Join(e.root, "github.com"), filepath.Join(e.root, "github.com", "o", "n.git"),
		filepath.Join(e.tmp, "outside.git.partial"), filepath.Join(e.root, "x.partial"), e.root + ".git.partial", "/", "",
	} {
		if err := e.m.discard(p); err == nil {
			t.Errorf("discard(%q) accepted", p)
		}
	}
	if _, err := os.Stat(filepath.Join(victim, "keep")); err != nil {
		t.Fatal("discard reached outside its partials")
	}
	ok := filepath.Join(e.root, "github.com", "o", "n.git.partial")
	if err := os.MkdirAll(filepath.Join(ok, "objects"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := e.m.discard(ok); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(ok); err == nil {
		t.Error("its own partial survived")
	}
}

// NoFetch is how a scan reads mirrors it must not change: the ones already on disk, as they
// are, and an error for anything that would need the network or a new directory.
func TestNoFetchServesWhatIsOnDiskAndChangesNothing(t *testing.T) {
	e := newTenv(t, nil)
	s := e.src("hangryclaude", "headroom", "repo")
	first := e.sync(s)

	ro, err := New(Config{Root: e.root, NoFetch: true, AllowLocal: true})
	if err != nil {
		t.Fatal(err)
	}
	moved := e.commit("README", "two\n", "upstream moves on")
	before := dirListing(t, e.root)

	r, err := ro.SyncResult(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Cloned || r.Absent || !maps.Equal(r.Before, r.After) || !maps.Equal(r.After, first.After) {
		t.Errorf("result = %+v, want the tips the mirror already had %v", r, first.After)
	}
	if r.After["refs/heads/main"] == moved {
		t.Error("the new upstream commit appeared although fetching is off")
	}
	b, a, err := ro.Sync(context.Background(), s)
	if err != nil || !maps.Equal(b, a) || !maps.Equal(a, first.After) {
		t.Errorf("Sync = %v %v %v", b, a, err)
	}
	if after := dirListing(t, e.root); after != before {
		t.Errorf("serving a mirror changed something under the root:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// No mirror for a source: an error that says so, and no directory made for it.
	other := e.src("hangryclaude", "other", "repo")
	if _, err := ro.SyncResult(context.Background(), other); err == nil || !strings.Contains(err.Error(), "fetching is off") {
		t.Errorf("a source with no mirror: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(ro.Path(other))); err == nil && dirListing(t, e.root) != before {
		t.Error("asking for a mirror that is not there made a directory")
	}

	// And a root that is not there is not made.
	absent := filepath.Join(e.tmp, "absent")
	if _, err := New(Config{Root: absent, NoFetch: true}); err == nil {
		t.Error("NoFetch accepted a root that does not exist")
	}
	if _, err := os.Stat(absent); err == nil {
		t.Error("NoFetch made the root")
	}
}

// dirListing lists everything under dir with its size and time, so a change shows as a difference.
func dirListing(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		lines = append(lines, strings.TrimPrefix(p, dir)+" "+strconv.FormatInt(fi.Size(), 10)+" "+strconv.FormatInt(fi.ModTime().UnixNano(), 10))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}
