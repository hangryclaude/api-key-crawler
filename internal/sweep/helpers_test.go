package sweep

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/fp"
	"keyguard/internal/triage"
)

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randStr(t testing.TB, charset string, n int) string {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = charset[x.Int64()]
	}
	return string(b)
}

// fakeKey builds a key-shaped value at run time from a prefix and random characters, so no
// secret-shaped literal exists in the repo. It is long and random enough to pass for a key.
func fakeKey(t testing.TB, prefix string, n int) string { return prefix + randStr(t, alnum, n) }

// isolate points every knob at a temp dir: keyguard's home, HOME, and git's global config,
// which gets an identity and no hooks. Nothing a test does can touch the real ones.
func isolate(t testing.TB) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("KEYGUARD_HOME", filepath.Join(root, "kg"))
	t.Setenv("HOME", filepath.Join(root, "home"))
	cfg := filepath.Join(root, "gitconfig")
	body := "[user]\n\tname = Test\n\temail = test@example.com\n[commit]\n\tgpgsign = false\n" +
		"[init]\n\tdefaultBranch = main\n[core]\n\thooksPath = /dev/null\n[advice]\n\tdetachedHead = false\n" +
		// A commit that adds many objects can start a background gc, which would still be
		// writing into the repo when the test's temp dir is removed.
		"[gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	return root
}

func runGit(t testing.TB, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// repo is a real git repository a test commits to.
type repo struct {
	t   testing.TB
	dir string
}

func newRepo(t testing.TB, dir string) *repo {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "init", "-q", "-b", "main")
	return &repo{t: t, dir: dir}
}

// commit writes files (an empty content deletes the file), commits everything and returns the sha.
func (r *repo) commit(msg string, files map[string]string) string {
	r.t.Helper()
	for p, content := range files {
		full := filepath.Join(r.dir, p)
		if content == "" {
			os.Remove(full)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			r.t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
	runGit(r.t, r.dir, "add", "-A")
	runGit(r.t, r.dir, "commit", "-q", "--allow-empty", "-m", msg)
	return runGit(r.t, r.dir, "rev-parse", "HEAD")
}

func (r *repo) git(args ...string) string { r.t.Helper(); return runGit(r.t, r.dir, args...) }

// gitEngine is a core.Engine that scans real git: it asks git which commits the Range
// selects, reads each commit's added lines, and reports the planted values it finds, the way
// gitleaks reports a line at the commit that added it. It records exactly which commits it
// was asked to look at, which is what the incremental-scan tests assert on.
type gitEngine struct {
	name, ver string
	kr        *fp.Keyring

	mu       sync.Mutex
	plants   map[string]plant // raw value -> how this engine reports it
	calls    []engineCall
	spans    []span
	err      error // returned by every ScanGit when set
	missing  bool  // Available() == false
	panicMsg string
	panicIn  string // when set, only a repo whose path contains this panics
	delay    time.Duration
	hook     func() // runs at the start of every ScanGit

	track *tracker // shared by every engine of a world, to see how many ran at once

	inflight, peak atomic.Int32
	gate           chan struct{} // when set, ScanGit blocks until it is closed
	entered        chan struct{} // receives one value per ScanGit that starts
}

type plant struct {
	typ     string
	verdict core.Verified
}

type engineCall struct {
	repo    string
	rng     core.Range
	opts    core.ScanOpts
	commits []string // oldest first
}

// span is when one ScanGit call ran, from entry to return.
type span struct {
	repo       string
	start, end time.Time
}

func newGitEngine(name string, kr *fp.Keyring) *gitEngine {
	return &gitEngine{name: name, ver: "1.0.0", kr: kr, plants: map[string]plant{}}
}

func (e *gitEngine) Name() string    { return e.name }
func (e *gitEngine) Version() string { e.mu.Lock(); defer e.mu.Unlock(); return e.ver }
func (e *gitEngine) Available() bool { e.mu.Lock(); defer e.mu.Unlock(); return !e.missing }
func (e *gitEngine) ScanStaged(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}
func (e *gitEngine) ScanDir(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}

func (e *gitEngine) plantValue(raw, typ string, v core.Verified) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.plants[raw] = plant{typ, v}
}

func (e *gitEngine) set(f func(*gitEngine)) { e.mu.Lock(); defer e.mu.Unlock(); f(e) }

func (e *gitEngine) callList() []engineCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.calls)
}

func (e *gitEngine) reset() { e.mu.Lock(); e.calls, e.spans = nil, nil; e.mu.Unlock() }

func (e *gitEngine) spanList() []span {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.spans)
}

func (e *gitEngine) ScanGit(ctx context.Context, repoDir string, r core.Range, o core.ScanOpts, emit core.Emit) error {
	t0 := time.Now()
	defer func() {
		e.mu.Lock()
		e.spans = append(e.spans, span{repo: repoDir, start: t0, end: time.Now()})
		e.mu.Unlock()
	}()
	if e.track != nil {
		e.track.enter()
		defer e.track.leave()
	}
	n := e.inflight.Add(1)
	defer e.inflight.Add(-1)
	for {
		p := e.peak.Load()
		if n <= p || e.peak.CompareAndSwap(p, n) {
			break
		}
	}
	e.mu.Lock()
	panicMsg, gate, entered, hook, delay := e.panicMsg, e.gate, e.entered, e.hook, e.delay
	e.mu.Unlock()
	if hook != nil {
		hook()
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if panicMsg != "" && strings.Contains(repoDir, e.panicIn) {
		panic(panicMsg)
	}
	if entered != nil {
		entered <- struct{}{}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	args := []string{"-C", repoDir, "rev-list", "--reverse"}
	if r.All {
		args = append(args, "--all")
	}
	args = append(args, r.Revs...)
	if !r.All && len(r.Revs) == 0 {
		return errors.New("fake engine: empty range")
	}
	out, err := exec.CommandContext(ctx, "git", append(args, "--")...).Output()
	if err != nil {
		return fmt.Errorf("fake engine: rev-list: %w", err)
	}
	commits := strings.Fields(string(out))
	e.mu.Lock()
	e.calls = append(e.calls, engineCall{repo: repoDir, rng: r, opts: o, commits: commits})
	fail := e.err
	plants := maps2(e.plants)
	e.mu.Unlock()
	if fail != nil {
		return fail
	}
	for _, c := range commits {
		diff, err := exec.CommandContext(ctx, "git", "-C", repoDir, "diff-tree", "-r", "-p", "-U0", "--root",
			"--no-commit-id", "--no-color", "--no-ext-diff", c).Output()
		if err != nil {
			return fmt.Errorf("fake engine: diff-tree: %w", err)
		}
		path, line := "", 0
		for _, ln := range strings.Split(string(diff), "\n") {
			switch {
			case strings.HasPrefix(ln, "+++ "):
				path = strings.TrimPrefix(strings.TrimPrefix(ln, "+++ "), "b/")
				if ln == "+++ /dev/null" {
					path = ""
				}
			case strings.HasPrefix(ln, "@@"):
				// @@ -a,b +c,d @@
				f := strings.Fields(ln)
				plus := strings.TrimPrefix(f[2], "+")
				start, _, _ := strings.Cut(plus, ",")
				line, _ = strconv.Atoi(start)
			case strings.HasPrefix(ln, "+") && path != "":
				text := ln[1:]
				for raw, pl := range plants {
					if strings.Contains(text, raw) {
						v := core.Unverified
						if o.Verify {
							v = pl.verdict
						}
						emit(core.Hit{
							Engine: e.name, Rule: e.name + "-" + pl.typ, Type: pl.typ, FP: e.kr.FP(raw), Shape: fp.Shape(raw),
							Len: len(raw), Entropy: fp.Entropy(raw), Verified: v, Context: fp.Context(text, raw),
							Loc: core.Location{Source: o.Loc.Source, Kind: o.Loc.Kind, Visibility: o.Loc.Visibility, Commit: c, Path: path, Line: line},
						})
					}
				}
				line++
			}
		}
	}
	return nil
}

func maps2[K comparable, V any](m map[K]V) map[K]V { return maps.Clone(m) }

// tracker counts how many scans run at the same time across all engines.
type tracker struct{ cur, peak atomic.Int32 }

func (t *tracker) enter() {
	n := t.cur.Add(1)
	for {
		p := t.peak.Load()
		if n <= p || t.peak.CompareAndSwap(p, n) {
			return
		}
	}
}
func (t *tracker) leave() { t.cur.Add(-1) }

// gitMirror keeps real bare mirrors of real origin repos, the way the production mirror
// does: clone --mirror once, fetch --prune after.
type gitMirror struct {
	t    testing.TB
	root string

	mu      sync.Mutex
	origins map[string]string // source id -> origin repo dir
	syncs   map[string]int
	fail    map[string]error
	order   []string // source ids in the order Sync was called
}

func newGitMirror(t testing.TB, root string) *gitMirror {
	return &gitMirror{t: t, root: root, origins: map[string]string{}, syncs: map[string]int{}, fail: map[string]error{}}
}

func (m *gitMirror) Path(s core.Source) string {
	return filepath.Join(m.root, strings.ReplaceAll(s.ID, "/", "__")+".git")
}

func (m *gitMirror) Sync(ctx context.Context, s core.Source) (before, after map[string]string, err error) {
	m.mu.Lock()
	origin, failure := m.origins[s.ID], m.fail[s.ID]
	m.syncs[s.ID]++
	m.order = append(m.order, s.ID)
	m.mu.Unlock()
	if failure != nil {
		return nil, nil, failure
	}
	dest := m.Path(s)
	if _, serr := os.Stat(dest); errors.Is(serr, os.ErrNotExist) {
		if out, err := exec.CommandContext(ctx, "git", "clone", "--mirror", "--quiet", origin, dest).CombinedOutput(); err != nil {
			return nil, nil, fmt.Errorf("clone: %w\n%s", err, out)
		}
		return map[string]string{}, m.refs(ctx, dest), nil
	}
	before = m.refs(ctx, dest)
	if out, err := exec.CommandContext(ctx, "git", "-C", dest, "fetch", "--quiet", "--prune", "origin").CombinedOutput(); err != nil {
		return nil, nil, fmt.Errorf("fetch: %w\n%s", err, out)
	}
	return before, m.refs(ctx, dest), nil
}

func (m *gitMirror) refs(ctx context.Context, dir string) map[string]string {
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "for-each-ref", "--format=%(objectname) %(refname)").Output()
	if err != nil {
		m.t.Errorf("for-each-ref: %v", err)
	}
	refs := map[string]string{}
	for _, ln := range strings.Split(string(out), "\n") {
		if sha, name, ok := strings.Cut(ln, " "); ok {
			refs[name] = sha
		}
	}
	return refs
}

func (m *gitMirror) syncCount(id string) int { m.mu.Lock(); defer m.mu.Unlock(); return m.syncs[id] }

func (m *gitMirror) syncOrder() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.order)
}

// fakeInventory answers like the real one: Changed reports a source when it is new, its
// visibility differs, or it was pushed since prev. Because it compares against prev, a
// source whose scan failed (so the snapshot did not advance) comes back, exactly as in
// production.
type fakeInventory struct {
	mu      sync.Mutex
	list    []core.Source
	events  []core.Event
	err     error // returned by Changed alongside its partial result
	hardErr error // returned by Changed instead of any result
	listErr error
	calls   struct{ list, changed int }
}

func (f *fakeInventory) List(ctx context.Context) ([]core.Source, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls.list++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return slices.Clone(f.list), nil
}

func (f *fakeInventory) Changed(ctx context.Context, prev map[string]core.Source) ([]core.Source, []core.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls.changed++
	if f.hardErr != nil {
		return nil, nil, f.hardErr
	}
	var changed []core.Source
	for _, s := range f.list {
		if p, ok := prev[s.ID]; !ok || p.Visibility != s.Visibility || s.PushedAt > p.PushedAt {
			changed = append(changed, s)
		}
	}
	ev := f.events
	f.events = nil // events are delivered once
	return changed, ev, f.err
}

func (f *fakeInventory) edit(id string, fn func(*core.Source)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.list {
		if f.list[i].ID == id {
			fn(&f.list[i])
			return
		}
	}
	panic("no such source " + id)
}

type notice struct {
	title, body string
	sev         core.Severity
}

type fakeNotifier struct {
	mu   sync.Mutex
	got  []notice
	fail error
}

func (n *fakeNotifier) Notify(title, body string, sev core.Severity) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.fail != nil {
		return n.fail
	}
	n.got = append(n.got, notice{title, body, sev})
	return nil
}

func (n *fakeNotifier) list() []notice { n.mu.Lock(); defer n.mu.Unlock(); return slices.Clone(n.got) }
func (n *fakeNotifier) count() int     { return len(n.list()) }

type fakeReporter struct {
	mu      sync.Mutex
	writes  int
	secrets []core.Secret
	run     core.RunStats
}

func (r *fakeReporter) Write(s []core.Secret, run core.RunStats, _ []core.LayerStatus) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writes++
	r.secrets, r.run = s, run
	return "report.html", nil
}

// fakeKnown is a KnownMatcher over a handful of planted values.
type fakeKnown struct {
	kr   *fp.Keyring
	mu   sync.Mutex
	set  []knownEntry
	ver  string
	hold chan struct{} // when set, every Match waits until it is closed
}

type knownEntry struct{ raw, name string }

func (k *fakeKnown) add(raw, name string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.set = append(k.set, knownEntry{raw, name})
}

func (k *fakeKnown) Len() int { k.mu.Lock(); defer k.mu.Unlock(); return len(k.set) }

func (k *fakeKnown) Match(data []byte) []core.KnownMatch {
	k.mu.Lock()
	set, hold := slices.Clone(k.set), k.hold
	k.mu.Unlock()
	if hold != nil {
		<-hold
	}
	var out []core.KnownMatch
	for _, e := range set {
		f := k.kr.FP(e.raw)
		for off := 0; ; {
			i := bytes.Index(data[off:], []byte(e.raw))
			if i < 0 {
				break
			}
			out = append(out, core.KnownMatch{
				EntryID: fp.ID(f), Name: e.name, Source: "/test/.env", Variant: "raw", Offset: off + i, Len: len(e.raw),
				FP: f, Shape: fp.Shape(e.raw),
			})
			off += i + len(e.raw)
		}
	}
	return out
}

// tickClock returns a time that moves forward one second per call, so "newest verdict wins"
// has an unambiguous order in tests.
type tickClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *tickClock { return &tickClock{t: time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)} }

// advance moves the clock forward without anyone asking the time: hours pass between polls.
func (c *tickClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *tickClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(time.Second)
	return c.t
}

// world is a complete fake GitHub plus keyguard's real db and triage, around real git repos.
type world struct {
	t       testing.TB
	root    string
	paths   core.Paths
	kr      *fp.Keyring
	inv     *fakeInventory
	mir     *gitMirror
	notif   *fakeNotifier
	rep     *fakeReporter
	store   *db.Store
	engines []*gitEngine
	origins map[string]*repo
	cfg     Config
	pushSeq int
	track   *tracker
	clock   *tickClock
	token   string            // what the fake token source hands out
	urls    map[string]string // resource page by event (source|type|at): core.Event has no URL of its own
}

func newWorld(t testing.TB) *world {
	root := isolate(t)
	paths := core.PathsAt(filepath.Join(root, "kg"))
	kr := fp.NewEphemeral()
	store, err := db.Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	w := &world{
		t: t, root: root, paths: paths, kr: kr, store: store, inv: &fakeInventory{},
		mir: newGitMirror(t, filepath.Join(root, "mirrors")), notif: &fakeNotifier{}, rep: &fakeReporter{},
		origins: map[string]*repo{}, token: fakeKey(t, "ghp_", 36), urls: map[string]string{},
	}
	track := &tracker{}
	w.track = track
	for _, n := range []string{"betterleaks", "trufflehog", "titus"} {
		e := newGitEngine(n, kr)
		e.track = track
		w.engines = append(w.engines, e)
	}
	clock := newClock()
	w.clock = clock
	w.cfg = Config{
		Paths: paths, Inventory: w.inv, Mirror: w.mir, Store: store,
		Triage:   triage.New(triage.WithStoreEvidence(store), triage.WithFingerprinter(kr)),
		Reporter: w.rep, Notifier: w.notif, Jobs: 4, Now: clock.Now,
	}
	for _, e := range w.engines {
		w.cfg.Engines = append(w.cfg.Engines, e)
	}
	w.cfg.Token = func(context.Context, string) (string, error) { return w.token, nil }
	w.cfg.EventURL = func(e core.Event) string { return w.urls[e.Source+"|"+e.Type+"|"+e.At] }
	return w
}

// event is an event about a resource's page. The page is kept on the side, since core.Event
// carries none; Config.EventURL looks it up the way the wired-up code reads it off the event.
func (w *world) event(source, typ, at, url string) core.Event {
	w.urls[source+"|"+typ+"|"+at] = url
	return core.Event{Source: source, Type: typ, At: at}
}

// addRepo creates a real origin repo and registers it with the fake inventory.
func (w *world) addRepo(name string, vis core.Visibility) *repo {
	w.t.Helper()
	r := newRepo(w.t, filepath.Join(w.root, "origins", name))
	id := "github.com/o/" + name
	w.origins[id] = r
	w.mir.origins[id] = r.dir
	w.pushSeq++
	w.inv.list = append(w.inv.list, core.Source{
		ID: id, Kind: "repo", Owner: "o", Name: name, Account: "o", Visibility: vis, DefaultBranch: "main",
		PushedAt: w.pushedAt(), SizeKB: 10,
	})
	return r
}

func (w *world) pushedAt() string {
	return time.Date(2026, 11, 3, 9, 0, w.pushSeq, 0, time.UTC).Format(time.RFC3339)
}

// pushed tells the fake inventory that a repo has new commits, as GitHub's pushedAt would.
func (w *world) pushed(name string) {
	w.pushSeq++
	at := w.pushedAt()
	w.inv.edit("github.com/o/"+name, func(s *core.Source) { s.PushedAt = at })
}

func (w *world) src(name string) string { return "github.com/o/" + name }

func (w *world) plantAll(raw, typ string, v core.Verified) {
	for _, e := range w.engines {
		e.plantValue(raw, typ, v)
	}
}

// runner builds a Runner from the world's config.
func (w *world) runner() *Runner {
	w.t.Helper()
	r, err := New(w.cfg)
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

func (w *world) resetCalls() {
	for _, e := range w.engines {
		e.reset()
	}
}

func (w *world) engineCalls() int {
	n := 0
	for _, e := range w.engines {
		n += len(e.callList())
	}
	return n
}

func (w *world) secret(raw string) core.Secret {
	w.t.Helper()
	s, ok := w.store.Get(w.kr.FP(raw))
	if !ok {
		w.t.Fatalf("no secret for the planted value (id would be %s)", fp.ID(w.kr.FP(raw)))
	}
	return s
}

// allFiles is everything under the keyguard home, joined: what a leak audit greps.
func (w *world) allFiles() string {
	w.t.Helper()
	var sb strings.Builder
	err := filepath.WalkDir(w.paths.Root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sb.WriteString(p + "\n")
		sb.Write(b)
		return nil
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return sb.String()
}

func mustPoll(t testing.TB, r *Runner) core.RunStats {
	t.Helper()
	st, err := r.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v\nnotes: %v", err, st.Notes)
	}
	return st
}

func mustFull(t testing.TB, r *Runner) core.RunStats {
	t.Helper()
	st, err := r.Full(context.Background())
	if err != nil {
		t.Fatalf("full: %v\nnotes: %v", err, st.Notes)
	}
	return st
}

func commitsOf(c engineCall) string { return strings.Join(shortAll(c.commits), ",") }

func shortAll(shas []string) []string {
	out := make([]string, len(shas))
	for i, s := range shas {
		out[i] = s[:7]
	}
	return out
}
