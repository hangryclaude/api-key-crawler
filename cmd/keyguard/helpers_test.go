package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/engines"
	"keyguard/internal/install"
	"keyguard/internal/inventory"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/inventory/ghcli/ghclitest"
	"keyguard/internal/mirror"
	"keyguard/internal/testkit"
)

// binPath is the real binary, built once. Most tests drive it the way git, Claude Code and
// launchd do; the tests that need to stand in for GitHub run the CLI in this process with
// the network seams replaced.
var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "keyguard-cmd-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binPath = filepath.Join(dir, "keyguard")
	build := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building the binary under test: %v\n%s", err, out)
		os.Exit(1)
	}
	// A test once wrote through a symlink and replaced the real trufflehog. Whatever the suite
	// does on this Mac, testkit fails the run if an engine binary is not what it was.
	code := testkit.Run(m)
	os.RemoveAll(dir) // made above, holds the one binary
	os.Exit(code)
}

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randStr(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(len(alnum))))
		if err != nil {
			t.Fatal(err)
		}
		b[i] = alnum[x.Int64()]
	}
	return string(b)
}

// fakeKey is a key-shaped value built at run time, so no secret-shaped literal is in this
// source. The body is re-rolled until it is random enough that no entropy gate drops it.
func fakeKey(t testing.TB, prefix string, n int) string {
	t.Helper()
	for {
		body := randStr(t, n)
		if entropy(body) >= 4.4 {
			return prefix + body
		}
	}
}

func entropy(s string) float64 {
	var cnt [256]int
	for i := 0; i < len(s); i++ {
		cnt[s[i]]++
	}
	var h float64
	for _, c := range cnt {
		if c > 0 {
			p := float64(c) / float64(len(s))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// machine is a throwaway Mac: its own HOME (so ~/.keyguard is under it), its own global git
// config, its own LaunchAgents dir. Nothing in a test can reach the real ones.
type machine struct {
	t         testing.TB
	dir       string
	home      string
	gitconfig string
	launch    string
	root      string // <home>/.keyguard
	env       []string
}

// enginesOnPath makes the engines the test kit finds visible to the installer's own search, which
// is PATH and then the directories under the machine's fake HOME. A CI run has a narrow PATH and
// the engines are wherever the test kit finds them; links in a directory of their own put them on
// PATH without widening it. Nothing is written through a link, and an engine that is missing is
// left for the test that needs it to ask testkit.EnginePath about.
func enginesOnPath(t testing.TB) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range engines.Names {
		if p, err := testkit.LookupEngine(name); err == nil {
			if err := os.Symlink(p, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func newMachine(t testing.TB) *machine {
	t.Helper()
	enginesOnPath(t)
	dir := t.TempDir()
	m := &machine{
		t: t, dir: dir, home: filepath.Join(dir, "home"), gitconfig: filepath.Join(dir, "gitconfig"),
		launch: filepath.Join(dir, "LaunchAgents"),
	}
	m.root = filepath.Join(m.home, ".keyguard")
	if err := os.MkdirAll(m.home, 0o755); err != nil {
		t.Fatal(err)
	}
	m.setGitConfig("[user]\n\tname = Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n" +
		"[gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n[advice]\n\tdetachedHead = false\n")
	// A whitelist, not a drop list: `keyguard learn` reads the environment, and a test machine
	// must not learn the real keys exported into the shell that runs the tests.
	keep := regexp.MustCompile(`^(PATH|TMPDIR|LANG|LC_ALL|USER|LOGNAME|SHELL)=`)
	for _, kv := range os.Environ() {
		if keep.MatchString(kv) {
			m.env = append(m.env, kv)
		}
	}
	m.env = append(m.env, "HOME="+m.home, "GIT_CONFIG_GLOBAL="+m.gitconfig, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	// The same isolation for tests that run the CLI in this process.
	t.Setenv("HOME", m.home)
	t.Setenv("KEYGUARD_HOME", "")
	t.Setenv("GIT_CONFIG_GLOBAL", m.gitconfig)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	return m
}

func (m *machine) setGitConfig(body string) {
	m.t.Helper()
	if err := os.WriteFile(m.gitconfig, []byte(body), 0o600); err != nil {
		m.t.Fatal(err)
	}
}

type result struct {
	out  string // stdout and stderr together
	code int
}

func (m *machine) run(dir, stdin, name string, args ...string) result {
	m.t.Helper()
	return m.runWith(nil, dir, stdin, name, args...)
}

// runWith is run with extra environment entries, which win over the machine's own.
func (m *machine) runWith(extra []string, dir, stdin, name string, args ...string) result {
	m.t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(slices.Clone(m.env), extra...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			m.t.Fatalf("%s: %v", name, err)
		}
	}
	return result{buf.String(), code}
}

// kg runs the built binary.
func (m *machine) kg(args ...string) result { m.t.Helper(); return m.run(m.dir, "", binPath, args...) }

// kgIn runs it with standard input.
func (m *machine) kgIn(stdin string, args ...string) result {
	m.t.Helper()
	return m.run(m.dir, stdin, binPath, args...)
}

// installed runs the installed copy, the one the hooks run.
func (m *machine) installed(args ...string) result {
	m.t.Helper()
	return m.run(m.dir, "", filepath.Join(m.root, "bin", "keyguard"), args...)
}

func (m *machine) git(dir string, args ...string) result {
	m.t.Helper()
	return m.run(dir, "", "git", args...)
}

func (m *machine) mustGit(dir string, args ...string) string {
	m.t.Helper()
	r := m.git(dir, args...)
	if r.code != 0 {
		m.t.Fatalf("git %s: exit %d\n%s", strings.Join(args, " "), r.code, r.out)
	}
	return strings.TrimSpace(r.out)
}

// install puts the hooks into the machine's global git config and the binary under its
// root; the launchd plists are written but never loaded (that would reach the real launchd).
// The engines are pinned where they are: a suite that copied a 170 MB trufflehog into every
// machine would take minutes. installFull is the real thing, for the tests about the copies.
func (m *machine) install() {
	m.t.Helper()
	if r := m.kg("install", "--no-bootstrap", "--in-place", "--launchd-dir", m.launch); r.code != 0 {
		m.t.Fatalf("install failed (%d):\n%s", r.code, r.out)
	}
}

// installFull is install with the engines copied into the machine's bin and pinned there.
func (m *machine) installFull() {
	m.t.Helper()
	if r := m.kg("install", "--no-bootstrap", "--launchd-dir", m.launch); r.code != 0 {
		m.t.Fatalf("install failed (%d):\n%s", r.code, r.out)
	}
}

func (m *machine) repo(name string) string {
	m.t.Helper()
	dir := filepath.Join(m.dir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		m.t.Fatal(err)
	}
	m.mustGit(dir, "init", "-q", "-b", "main")
	return dir
}

func (m *machine) write(rel, body string) string {
	m.t.Helper()
	p := rel
	if !filepath.IsAbs(rel) {
		p = filepath.Join(m.dir, rel)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		m.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		m.t.Fatal(err)
	}
	return p
}

// learn teaches the machine one key by putting it in a .env under ~/dev and running learn.
func (m *machine) learn(name, value string) {
	m.t.Helper()
	m.write(filepath.Join(m.home, "dev", "proj", ".env"), name+"="+value+"\n")
	if r := m.kg("learn", "--no-engine", "--no-gh"); r.code != 0 {
		m.t.Fatalf("learn: %d\n%s", r.code, r.out)
	}
}

// ----- the in-process CLI, with GitHub replaced -----

// world is the CLI run in this process against a fake GitHub made of local repos: the
// inventory lists them, the mirror clones them from disk.
type world struct {
	m       *machine
	t       testing.TB
	paths   core.Paths
	origins map[string]string // source id -> origin repo dir
	srcs    []core.Source
	listed  int
	changed int
	seams   seams
	notices *notices
	opened  []string
	mu      sync.Mutex
}

type notices struct {
	mu  sync.Mutex
	got []notice
}
type notice struct {
	title, body string
	sev         core.Severity
}

func (n *notices) Notify(title, body string, sev core.Severity) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, notice{title, body, sev})
	return nil
}

func (n *notices) list() []notice { n.mu.Lock(); defer n.mu.Unlock(); return slices.Clone(n.got) }

// fakeInv is the inventory over the world's sources.
type fakeInv struct{ w *world }

func (f fakeInv) List(context.Context) ([]core.Source, error) {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	f.w.listed++
	return slices.Clone(f.w.srcs), nil
}

func (f fakeInv) Changed(_ context.Context, prev map[string]core.Source) ([]core.Source, []core.Event, error) {
	f.w.mu.Lock()
	defer f.w.mu.Unlock()
	f.w.changed++
	var out []core.Source
	for _, s := range f.w.srcs {
		if p, ok := prev[s.ID]; !ok || p.Visibility != s.Visibility || s.PushedAt > p.PushedAt {
			out = append(out, s)
		}
	}
	return out, nil, nil
}

func newWorld(t testing.TB) *world {
	t.Helper()
	m := newMachine(t)
	w := &world{m: m, t: t, paths: core.PathsAt(m.root), origins: map[string]string{}, notices: &notices{}}
	w.seams = seams{
		inventory: func(_ install.Config, _ core.Paths) (core.Inventory, error) { return fakeInv{w}, nil },
		mirror: func(p core.Paths) (mirrorAPI, error) {
			return mirror.New(mirror.Config{Root: p.Mirrors, AllowLocal: true})
		},
		notifier: w.notices,
		open:     func(path string) error { w.opened = append(w.opened, path); return nil },
		// Nothing a test runs may reach the real gh or the real launchd: a fake GitHub that knows
		// no repo, and a runner that answers for gh and launchctl and runs only git for real.
		gh: ghcli.New(ghclitest.New(t, func(ghclitest.Call) ghclitest.Reply {
			return ghclitest.JSON(404, map[string]string{"message": "Not Found"})
		}, "o")),
		run: offlineRun,
	}
	return w
}

// offlineRun is the Runner of a test machine: gh answers with a placeholder, launchctl knows no
// job, and everything else (git) is real.
func offlineRun(ctx context.Context, name string, args ...string) ([]byte, error) {
	switch name {
	case "gh":
		return []byte("placeholder-not-a-token\n"), nil
	case "launchctl":
		return nil, os.ErrNotExist
	}
	return install.ExecRunner(ctx, name, args...)
}

// addRepo makes a real origin repo and lists it as a source.
func (w *world) addRepo(name string, vis core.Visibility) string {
	w.t.Helper()
	dir := w.m.repo("origins/" + name)
	id := "github.com/o/" + name
	w.origins[id] = dir
	w.mu.Lock()
	w.srcs = append(w.srcs, core.Source{
		ID: id, Kind: "repo", Owner: "o", Name: name, Account: "o", CloneURL: "file://" + dir,
		Visibility: vis, PushedAt: time.Date(2026, 11, 3, 9, 0, len(w.srcs), 0, time.UTC).Format(time.RFC3339), SizeKB: 1,
	})
	w.mu.Unlock()
	return dir
}

// pushed moves a source's pushedAt, as a push to it would.
func (w *world) pushed(name string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i := range w.srcs {
		if w.srcs[i].Name == name {
			w.srcs[i].PushedAt = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Second).Format(time.RFC3339)
		}
	}
}

func (w *world) commit(repo, msg string, files map[string]string) {
	w.t.Helper()
	for p, body := range files {
		w.m.write(filepath.Join(repo, p), body)
	}
	w.m.mustGit(repo, "add", "-A")
	w.m.mustGit(repo, "commit", "-q", "-m", msg)
}

// cli runs a command in this process and returns what it printed and its exit code.
func (w *world) cli(args ...string) (stdout, stderr string, code int) {
	w.t.Helper()
	var out, errb bytes.Buffer
	c := &cli{ctx: context.Background(), in: strings.NewReader(""), out: &out, err: &errb, seams: w.seams}
	code = c.dispatch(args)
	return out.String(), errb.String(), code
}

func (w *world) mustCLI(args ...string) string {
	w.t.Helper()
	out, errs, code := w.cli(args...)
	if code != 0 {
		w.t.Fatalf("keyguard %s: exit %d\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), code, out, errs)
	}
	return out
}

// config writes state/config.json so a test chooses its engines (no network from a
// verifying engine, no dependence on trufflehog being healthy) and its iMessage target.
func (w *world) config(poll ...string) {
	w.t.Helper()
	body := `{"tiers":{"poll":["` + strings.Join(poll, `","`) + `"],"deep":["` + strings.Join(poll, `","`) + `"]}}`
	w.m.write(w.paths.Config, body)
}

func (w *world) saveInventorySnapshot() {
	w.t.Helper()
	if err := inventory.SaveSnapshot(w.paths.Inventory, w.srcs, time.Now()); err != nil {
		w.t.Fatal(err)
	}
}
