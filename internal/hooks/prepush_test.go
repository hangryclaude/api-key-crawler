package hooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/core"
)

// pushWorld is a clone with a bare origin: c1,c2 are pushed, c3 is local only.
type pushWorld struct {
	e              *tenv
	repo, remote   string
	c1, c2, c3     string
	tag            string // an annotated tag on c3
	stderr         strings.Builder
	mu             sync.Mutex
	ranges         [][]string
	verifiedRanges [][]string
}

func newPushWorld(t *testing.T) *pushWorld {
	t.Helper()
	e := newTenv(t)
	w := &pushWorld{e: e}
	w.remote = e.initBare("origin.git")
	w.repo = e.initRepo("r")
	e.must(w.repo, "remote", "add", "origin", w.remote)
	// The hooks are exercised in-process by these tests, so history is built without them.
	w.c1 = e.quietCommit(w.repo, "a.txt", "1\n", "c1")
	w.c2 = e.quietCommit(w.repo, "b.txt", "2\n", "c2")
	e.mustQuiet(w.repo, "push", "-q", "-u", "origin", "main")
	w.c3 = e.quietCommit(w.repo, "c.txt", "3\n", "c3")
	e.mustQuiet(w.repo, "tag", "-a", "v1", "-m", "release", "HEAD")
	w.tag = e.must(w.repo, "rev-parse", "v1")
	return w
}

func (w *pushWorld) deps() Deps {
	return Deps{
		Dir: w.repo, Stderr: &w.stderr, FP: testKeyring,
		ScanRange: func(ctx context.Context, repo string, r core.Range, emit core.Emit) error {
			w.mu.Lock()
			w.ranges = append(w.ranges, append([]string(nil), r.Revs...))
			w.mu.Unlock()
			return nil
		},
		ScanVerified: func(ctx context.Context, repo string, r core.Range, emit core.Emit) error {
			w.mu.Lock()
			w.verifiedRanges = append(w.verifiedRanges, append([]string(nil), r.Revs...))
			w.mu.Unlock()
			return nil
		},
	}
}

func (w *pushWorld) push(d Deps, remote, url, stdin string) int {
	w.stderr.Reset()
	w.ranges, w.verifiedRanges = nil, nil
	return PrePush(context.Background(), d, []string{remote, url}, strings.NewReader(stdin))
}

func TestPrePushRange(t *testing.T) {
	w := newPushWorld(t)
	w.e.activate()
	d := w.deps()
	unknown := strings.Repeat("ab", 20)

	for _, c := range []struct {
		name   string
		remote string
		stdin  string
		want   [][]string // nil: nothing may be scanned
	}{
		{"update of a pushed branch", "origin",
			fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", w.c3, w.c2),
			[][]string{{w.c3, "--not", "--remotes=origin", w.c2}}},
		{"new branch", "origin",
			fmt.Sprintf("refs/heads/feat %s refs/heads/feat %s\n", w.c3, zeroOID),
			[][]string{{w.c3, "--not", "--remotes=origin"}}},
		{"new tag", "origin",
			fmt.Sprintf("refs/tags/v1 %s refs/tags/v1 %s\n", w.tag, zeroOID),
			[][]string{{w.tag, "--not", "--remotes=origin"}}},
		{"deletion is skipped", "origin",
			fmt.Sprintf("(delete) %s refs/heads/old %s\n", zeroOID, w.c2),
			nil},
		{"remote sha we never fetched is left out", "origin",
			fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", w.c3, unknown),
			[][]string{{w.c3, "--not", "--remotes=origin"}}},
		{"nothing new to send", "origin",
			fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", w.c2, w.c1),
			nil},
		{"several refs make one range", "origin",
			fmt.Sprintf("refs/heads/main %s refs/heads/main %s\nrefs/tags/v1 %s refs/tags/v1 %s\n(delete) %s refs/heads/old %s\n", w.c3, w.c2, w.tag, zeroOID, zeroOID, w.c1),
			[][]string{{w.c3, w.tag, "--not", "--remotes=origin", w.c2}}},
		{"a URL instead of a remote name excludes nothing by name", "https://example.com/o/r.git",
			fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", w.c3, w.c2),
			[][]string{{w.c3, "--not", w.c2}}},
		{"a path remote", "../origin.git",
			fmt.Sprintf("refs/heads/feat %s refs/heads/feat %s\n", w.c3, zeroOID),
			[][]string{{w.c3}}},
		{"a pattern-looking remote is never used as a glob", "or*gin",
			fmt.Sprintf("refs/heads/feat %s refs/heads/feat %s\n", w.c3, zeroOID),
			[][]string{{w.c3}}},
		{"garbage lines are ignored", "origin", "nonsense\n\n", nil},
	} {
		code := w.push(d, c.remote, c.remote, c.stdin)
		if code != 0 {
			t.Errorf("%s: code %d:\n%s", c.name, code, w.stderr.String())
		}
		if !reflect.DeepEqual(w.ranges, c.want) {
			t.Errorf("%s: scanned %v, want %v", c.name, w.ranges, c.want)
		}
	}
}

func TestPrePushVerifiedPassOnlyForExposedRemotes(t *testing.T) {
	w := newPushWorld(t)
	w.e.activate()
	stdin := fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", w.c3, w.c2)

	for _, c := range []struct {
		vis  core.Visibility
		set  bool
		want bool
	}{
		{core.Public, true, true},
		{core.Unknown, true, true},
		{core.SecretGist, true, true},
		{"", false, true}, // no lookup wired in: unknown, so the cautious answer
		{core.Private, true, false},
		{core.Local, true, false},
	} {
		d := w.deps()
		if c.set {
			vis := c.vis
			d.Visibility = func(remote, url string) core.Visibility { return vis }
		}
		w.push(d, "origin", "git@github.com:o/r.git", stdin)
		if got := len(w.verifiedRanges) > 0; got != c.want {
			t.Errorf("visibility %q: verified pass ran = %v, want %v", c.vis, got, c.want)
		}
		if len(w.ranges) != 1 {
			t.Errorf("visibility %q: regex pass ran %d times, want 1", c.vis, len(w.ranges))
		}
	}

	// The lookup is given the remote's name and URL.
	var gotRemote, gotURL string
	d := w.deps()
	d.Visibility = func(remote, url string) core.Visibility { gotRemote, gotURL = remote, url; return core.Private }
	w.push(d, "origin", "git@github.com:o/r.git", stdin)
	if gotRemote != "origin" || gotURL != "git@github.com:o/r.git" {
		t.Errorf("lookup got (%q, %q)", gotRemote, gotURL)
	}
}

func TestPrePushBlocksOnlyVerifiedLiveHitsFromTheVerifyingPass(t *testing.T) {
	w := newPushWorld(t)
	w.e.activate()
	stdin := fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", w.c3, w.c2)
	d := w.deps()
	d.Visibility = func(string, string) core.Visibility { return core.Public }
	d.ScanVerified = func(ctx context.Context, repo string, r core.Range, emit core.Emit) error {
		emit(core.Hit{Engine: "trufflehog", Rule: "GitHub", Type: "github", FP: "feedfacefeedfacefeedfacefeedface", Shape: "ghp_…", Verified: core.Unverified, Loc: core.Location{Path: "u.txt", Line: 1}})
		emit(core.Hit{Engine: "trufflehog", Rule: "AWS", Type: "aws", FP: "0123456789abcdef0123456789abcdef", Shape: "AKIA…", Verified: core.VerifyError, Loc: core.Location{Path: "e.txt", Line: 1}})
		return nil
	}
	if code := w.push(d, "origin", "u", stdin); code != 0 {
		t.Errorf("unverified hits from the verifying pass blocked a push:\n%s", w.stderr.String())
	}

	d.ScanVerified = func(ctx context.Context, repo string, r core.Range, emit core.Emit) error {
		emit(core.Hit{Engine: "trufflehog", Rule: "GitHub", Type: "github", FP: "feedfacefeedfacefeedfacefeedface", Shape: "ghp_…c0de", Verified: core.Live,
			Loc: core.Location{Path: "live.txt", Line: 7, Commit: w.c3}})
		return nil
	}
	if code := w.push(d, "origin", "u", stdin); code != 1 {
		t.Fatalf("a verified live key did not block (code %d):\n%s", code, w.stderr.String())
	}
	for _, want := range []string{"push blocked", "live.txt", "verified live", "ghp_…c0de", w.c3[:7], "kgfeedf"} {
		if !strings.Contains(w.stderr.String(), want) {
			t.Errorf("message lacks %q:\n%s", want, w.stderr.String())
		}
	}

	// Hits the regex pass reports as unverified still block, on any remote.
	d.Visibility = func(string, string) core.Visibility { return core.Private }
	d.ScanRange = func(ctx context.Context, repo string, r core.Range, emit core.Emit) error {
		emit(core.Hit{Engine: "betterleaks", Rule: "generic-api-key", Type: "generic", FP: "aaaabbbbccccddddaaaabbbbccccdddd", Shape: "…", Loc: core.Location{Path: "g.txt", Line: 2}})
		return nil
	}
	if code := w.push(d, "origin", "u", stdin); code != 1 {
		t.Errorf("regex hit on a private remote did not block (code %d)", code)
	}
}

func TestPrePushFailsOpenAndSaysWhy(t *testing.T) {
	w := newPushWorld(t)
	w.e.activate()
	stdin := fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", w.c3, w.c2)
	d := w.deps()
	d.ScanRange = func(context.Context, string, core.Range, core.Emit) error { return errors.New("engine exploded") }
	d.ScanVerified = func(context.Context, string, core.Range, core.Emit) error { panic("verifier bug") }
	if code := w.push(d, "origin", "u", stdin); code != 0 {
		t.Fatalf("code %d, want 0:\n%s", code, w.stderr.String())
	}
	for _, want := range []string{"regex engine", "engine exploded", "verifying engine", "panic"} {
		if !strings.Contains(w.stderr.String(), want) {
			t.Errorf("warning lacks %q:\n%s", want, w.stderr.String())
		}
	}
	// A learned key still stops the push when the engines are down.
	key := fakeGitHub()
	w.e.must(w.repo, "branch", "-q", "tmp")
	w.e.quietCommit(w.repo, "k.txt", key+"\n", "c4 holds a key")
	c4 := w.e.must(w.repo, "rev-parse", "HEAD")
	d.Known = newSubMatcher([]string{"K=" + key})
	if code := w.push(d, "origin", "u", fmt.Sprintf("refs/heads/main %s refs/heads/main %s\n", c4, w.c2)); code != 1 {
		t.Errorf("learned key did not block with the engines down (code %d):\n%s", code, w.stderr.String())
	}
	assertNoLeak(t, "stderr", w.stderr.String(), key)
}

func TestPrePushCleanPushesPass(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	remote := e.initBare("origin.git")
	repo := e.initRepo("r")
	e.must(repo, "remote", "add", "origin", remote)
	e.commitFile(repo, "a.txt", "1\n", "c1")

	for _, step := range [][]string{
		{"push", "-q", "-u", "origin", "main"}, // new branch
		{"push", "-q", "origin", "main"},       // nothing new
		{"checkout", "-q", "-b", "feat"},
		{"push", "-q", "-u", "origin", "feat"}, // another new branch, nothing new on it
	} {
		if r := e.git(repo, step...); r.code != 0 {
			t.Fatalf("git %v:\n%s", step, r)
		}
	}
	e.commitFile(repo, "b.txt", "2\n", "c2")
	e.must(repo, "tag", "-a", "v1", "-m", "r")
	e.must(repo, "tag", "light")
	for _, step := range [][]string{
		{"push", "-q", "origin", "feat"},
		{"push", "-q", "origin", "--tags"},
		{"push", "-q", "origin", "feat:renamed"},
		{"push", "-q", "origin", "--delete", "renamed"}, // deletion sends no commits
		{"push", "-q", "origin", ":feat"},
		{"push", "-q", "--force", "origin", "main"},
	} {
		if r := e.git(repo, step...); r.code != 0 {
			t.Errorf("git %v was refused:\n%s", step, r)
		}
	}
	if e.must(remote, "rev-parse", "refs/tags/v1") == "" {
		t.Errorf("tag did not arrive")
	}
}

// Push options (-o) go to the server, not to the hook: they must not change what is scanned.
func TestPrePushWithPushOptionsIsStillScanned(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	remote := e.initBare("origin.git")
	e.must(remote, "config", "receive.advertisePushOptions", "true")
	repo := e.initRepo("r")
	e.must(repo, "remote", "add", "origin", remote)
	e.commitFile(repo, "a.txt", "1\n", "c1")
	if r := e.git(repo, "push", "-q", "-o", "ci.skip", "-o", "x=y", "-u", "origin", "main"); r.code != 0 {
		t.Fatalf("clean push with options was refused:\n%s", r)
	}
	key := fakeGitHub()
	e.write(repo, "k.txt", "t=\""+key+"\"\n")
	e.must(repo, "add", "k.txt")
	e.must(repo, "commit", "--no-verify", "-q", "-m", "oops")
	r := e.git(repo, "push", "-o", "ci.skip", "origin", "main")
	if r.code == 0 || !strings.Contains(r.err, "push blocked") {
		t.Errorf("a push with an option skipped the scan:\n%s", r)
	}
	assertNoLeak(t, "stderr", r.err, key)
}

// What the remote already holds is not re-judged: a key that leaked earlier is the poll's
// problem, and must not hold up every later clean push.
func TestPrePushDoesNotRescanWhatTheRemoteHolds(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	remote := e.initBare("origin.git")
	repo := e.initRepo("r")
	e.must(repo, "remote", "add", "origin", remote)
	key := fakeGitHub()
	e.setKnown(map[string]string{"K": key})
	e.quietCommit(repo, "a.txt", "1\n", "c1")
	e.quietCommit(repo, "k.txt", "t="+key+"\n", "c2 holds a key")
	e.mustQuiet(repo, "push", "-q", "-u", "origin", "main") // it already leaked

	e.commitFile(repo, "b.txt", "2\n", "clean")
	if r := e.git(repo, "push", "-q", "origin", "main"); r.code != 0 {
		t.Errorf("a clean push after an old leak was refused:\n%s", r)
	}
	e.must(repo, "checkout", "-q", "-b", "feat")
	e.commitFile(repo, "c.txt", "3\n", "clean on a branch")
	if r := e.git(repo, "push", "-q", "-u", "origin", "feat"); r.code != 0 {
		t.Errorf("a new branch with one clean commit was refused:\n%s", r)
	}
	// A different remote has not seen it, though: the same history is judged there.
	other := e.initBare("other.git")
	e.must(repo, "remote", "add", "other", other)
	r := e.git(repo, "push", "-q", "other", "main")
	if r.code == 0 || !strings.Contains(r.err, "learned key K") {
		t.Errorf("pushing the leaked history to a second remote must be refused:\n%s", r)
	}
	assertNoLeak(t, "stderr", r.err, key)
}

// A learned key already in the commits being sent is caught by the matcher, once, even
// though the regex engine sees it too.
func TestPrePushLearnedKeyIsReportedOnce(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	remote := e.initBare("origin.git")
	repo := e.initRepo("r")
	e.must(repo, "remote", "add", "origin", remote)
	key := fakeGitHub()
	e.setKnown(map[string]string{"GITHUB_TOKEN": key})
	e.quietCommit(repo, "a.txt", "1\n", "c1")
	e.quietCommit(repo, "app/cfg.py", "T = \""+key+"\"\n", "c2")

	r := e.git(repo, "push", "origin", "main")
	if r.code == 0 {
		t.Fatalf("push of a learned key went through:\n%s", r)
	}
	if n := strings.Count(r.err, "app/cfg.py"); n != 1 {
		t.Errorf("the finding is listed %d times, want once (known and engine agree):\n%s", n, r.err)
	}
	if !strings.Contains(r.err, "learned key GITHUB_TOKEN") {
		t.Errorf("the learned-key row should win the merge:\n%s", r.err)
	}
	if e.git(remote, "rev-parse", "--verify", "-q", "main").code == 0 {
		t.Errorf("the remote got a branch")
	}
	assertNoLeak(t, "stderr", r.err, key)
}

// The verifying pass, end to end through git: a public remote gets it, a private one does
// not; only a live hit blocks.
func TestPrePushVerifyingPassThroughGit(t *testing.T) {
	t.Parallel()
	e := newTenv(t)
	remote := e.initBare("origin.git")
	repo := e.initRepo("r")
	e.must(repo, "remote", "add", "origin", remote)
	e.commitFile(repo, "a.txt", "1\n", "c1")
	log := filepath.Join(e.root, "verified.log")
	e.extra["KG_TEST_VERIFIED_LOG"] = log

	e.extra["KG_TEST_VIS"] = "private"
	if r := e.git(repo, "push", "-q", "-u", "origin", "main"); r.code != 0 {
		t.Fatalf("private push:\n%s", r)
	}
	if _, err := os.Stat(log); err == nil {
		t.Errorf("the verifying pass ran for a private remote")
	}

	e.commitFile(repo, "b.txt", "2\n", "c2")
	e.extra["KG_TEST_VIS"] = "public"
	if r := e.git(repo, "push", "-q", "origin", "main"); r.code != 0 {
		t.Fatalf("public push with only an unverified hit was refused:\n%s", r)
	}
	if b, err := os.ReadFile(log); err != nil || !strings.Contains(string(b), "--not") {
		t.Errorf("the verifying pass did not run for a public remote: %v %q", err, b)
	}

	e.commitFile(repo, "c.txt", "3\n", "c3")
	e.extra["KG_TEST_LIVE_FP"] = "0123456789abcdef0123456789abcdef"
	r := e.git(repo, "push", "-q", "origin", "main")
	if r.code == 0 || !strings.Contains(r.err, "verified live") {
		t.Errorf("a live hit must block:\n%s", r)
	}
}
