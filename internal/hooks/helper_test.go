package hooks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/testkit"
)

// Tests drive the real hooks through real git. The hook command in the test git config is
// this very test binary, re-executed in helper mode (the os.Args re-exec pattern), wired
// with a plain-substring KnownMatcher over fakes registered at run time and with the real
// betterleaks binary for the engine passes. The test process finds betterleaks through
// testkit and hands the path to each helper in KEYGUARD_TEST_BETTERLEAKS (see newTenv).

const helperEnv = "KG_HOOKS_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		os.Exit(helperMain(os.Args[1:]))
	}
	testkit.Main(m) // betterleaks runs in these tests: hash it before and after
}

// testKeyring is shared by the test process and the helper so both compute the same
// fingerprints for the same fake.
var testKeyring = fp.FromSalt(bytes.Repeat([]byte{0x42}, 40))

// helperMain is what git runs as a hook: `<test binary> hook <name> [args...]`.
func helperMain(args []string) int {
	if len(args) < 2 || args[0] != "hook" {
		fmt.Fprintln(os.Stderr, "hooks test helper: usage: hook <name> [args]")
		return 3
	}
	return Run(context.Background(), args[1], args[2:], os.Stdin, helperDeps())
}

// helperDeps builds Deps from the environment the test process set for git.
func helperDeps() Deps {
	d := Deps{FP: testKeyring, Stderr: os.Stderr}
	if v := os.Getenv("KG_TEST_FAKES"); v != "" {
		d.Known = newSubMatcher(strings.Split(v, "\n"))
	}
	if os.Getenv("KG_TEST_NO_ENGINE") != "1" {
		d.ScanStaged = func(ctx context.Context, dir string, emit core.Emit) error {
			return runBetterleaks(ctx, dir, []string{"git", "--pre-commit", "--staged"}, emit)
		}
		d.ScanRange = func(ctx context.Context, dir string, r core.Range, emit core.Emit) error {
			return runBetterleaks(ctx, dir, []string{"git", "--log-opts", strings.Join(r.Revs, " ")}, emit)
		}
	}
	if log := os.Getenv("KG_TEST_VERIFIED_LOG"); log != "" {
		// A stand-in for trufflehog: records that it ran, and reports one live and one
		// unverified hit so the caller's filtering can be seen.
		d.ScanVerified = func(ctx context.Context, dir string, r core.Range, emit core.Emit) error {
			f, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			fmt.Fprintln(f, strings.Join(r.Revs, " "))
			f.Close()
			if live := os.Getenv("KG_TEST_LIVE_FP"); live != "" {
				emit(core.Hit{Engine: "trufflehog", Rule: "Test", Type: "test", FP: live, Shape: "ghp_…", Verified: core.Live, Loc: core.Location{Path: "live.txt", Line: 1}})
			}
			emit(core.Hit{Engine: "trufflehog", Rule: "Test", Type: "test", FP: "00unverified", Shape: "x…", Verified: core.Unverified, Loc: core.Location{Path: "unverified.txt", Line: 1}})
			return nil
		}
	}
	vis := core.Visibility(os.Getenv("KG_TEST_VIS"))
	if vis != "" {
		d.Visibility = func(string, string) core.Visibility { return vis }
	}
	if v := os.Getenv("KG_TEST_IGNORE"); v != "" {
		ignored := map[string]bool{}
		for _, x := range strings.Split(v, ",") {
			ignored[x] = true
		}
		d.Ignored = func(fp string) bool { return ignored[fp] }
	}
	return d
}

// subMatcher is the test KnownMatcher: exact substring search over registered fakes.
type subMatcher struct {
	names []string
	vals  []string
}

// newSubMatcher takes "NAME=value" lines.
func newSubMatcher(lines []string) *subMatcher {
	m := &subMatcher{}
	for _, l := range lines {
		if name, val, ok := strings.Cut(l, "="); ok && val != "" {
			m.names = append(m.names, name)
			m.vals = append(m.vals, val)
		}
	}
	return m
}

func (m *subMatcher) Len() int { return len(m.vals) }

func (m *subMatcher) Match(data []byte) []core.KnownMatch {
	var out []core.KnownMatch
	for i, v := range m.vals {
		for off := 0; ; {
			j := bytes.Index(data[off:], []byte(v))
			if j < 0 {
				break
			}
			fpv := testKeyring.FP(v)
			out = append(out, core.KnownMatch{
				EntryID: fp.ID(fpv), Name: m.names[i], Source: "test", Variant: "raw",
				Offset: off + j, Len: len(v), FP: fpv, Shape: fp.Shape(v),
			})
			off += j + 1
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}

// finding is the part of a betterleaks JSON record the test normalizer reads.
type finding struct {
	RuleID    string
	File      string
	StartLine int
	Secret    string
	Match     string
	Entropy   float64
	Commit    string
}

// runBetterleaks is a test-only normalizer: it streams the engine's JSON, fingerprints
// each secret and drops the raw value, the way internal/engines does for production.
func runBetterleaks(ctx context.Context, dir string, args []string, emit core.Emit) error {
	bin, err := testkit.LookupEngine("betterleaks")
	if err != nil {
		return fmt.Errorf("betterleaks: %w", err)
	}
	// --ignore-gitleaks-allow on every call, as the production engines pass it (STEAL P0-12, K9):
	// a comment in the committed file must not be able to silence the scan.
	full := append(append([]string{}, args...), "-r", "-", "-f", "json", "--no-banner", "--no-color", "-l", "error", "--ignore-gitleaks-allow")
	cmd := exec.CommandContext(ctx, bin, full...)
	cmd.Dir = dir
	cmd.Stderr = io.Discard
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var all []finding
	derr := json.NewDecoder(out).Decode(&all)
	_, _ = io.Copy(io.Discard, out)
	werr := cmd.Wait()
	var ee *exec.ExitError
	if werr != nil && !(errors.As(werr, &ee) && ee.ExitCode() == 1) { // 1 = leaks found
		return fmt.Errorf("betterleaks: %w", werr)
	}
	if derr != nil && derr != io.EOF {
		return fmt.Errorf("betterleaks output: %w", derr)
	}
	for _, f := range all {
		emit(core.Hit{
			Engine: "betterleaks", Rule: f.RuleID, Type: f.RuleID,
			FP: testKeyring.FP(f.Secret), Shape: fp.Shape(f.Secret), Len: len(f.Secret), Entropy: f.Entropy,
			Verified: core.Unverified, Context: fp.Context(f.Match, f.Secret),
			Loc: core.Location{Path: f.File, Line: f.StartLine, Commit: f.Commit},
		})
	}
	return nil
}

// ---- fakes ----

const (
	alnum     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	urlsafe64 = alnum + "-_"
)

func randString(n int, charset string) string {
	b := make([]byte, n)
	for i := range b {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(err)
		}
		b[i] = charset[k.Int64()]
	}
	return string(b)
}

// fakeGitHub is shaped like a GitHub personal access token: prefix + 36 random alphanumerics.
func fakeGitHub() string { return "ghp_" + randString(36, alnum) }

// fakeAnthropic is shaped like an Anthropic API key.
func fakeAnthropic() string { return "sk-ant-api03-" + randString(93, urlsafe64) + "AA" }

// fakePEM is a private-key block with a random body; it parses as no key.
func fakePEM() string {
	return "-----BEGIN " + "PRIVATE KEY-----\n" + randString(64, alnum) + "\n" + randString(64, alnum) + "\n-----END " + "PRIVATE KEY-----\n"
}

// assertNoLeak fails when text contains the fake, or any 10-character window of it. The
// shape shows a public prefix and at most four trailing characters, so no window of ten
// can legitimately appear.
func assertNoLeak(t *testing.T, where, text string, fakes ...string) {
	t.Helper()
	for _, f := range fakes {
		for i := 0; i+10 <= len(f); i++ {
			if strings.Contains(text, f[i:i+10]) {
				t.Errorf("%s leaks part of a secret (window at %d):\n%s", where, i, text)
				return
			}
		}
	}
}

// ---- environment ----

// tenv is one isolated world: its own HOME, KEYGUARD_HOME and global git config, whose
// hooks are the test helper. Nothing here touches the real ~/.gitconfig or ~/.keyguard.
type tenv struct {
	t         *testing.T
	root      string
	home      string
	kgHome    string
	gitconfig string
	extra     map[string]string // env for git and the hooks it runs
	mu        sync.Mutex
}

func newTenv(t *testing.T) *tenv {
	t.Helper()
	root := t.TempDir()
	e := &tenv{t: t, root: root, home: filepath.Join(root, "home"), kgHome: filepath.Join(root, "kg"),
		gitconfig: filepath.Join(root, "gitconfig"), extra: map[string]string{}}
	// The helper runs under this world's fake HOME and a git-scrubbed environment, so it gets
	// the engine as a pin rather than a search. A machine without betterleaks skips these
	// tests (CI fails them): nearly all of them run it.
	e.extra[testkit.OverrideEnv("betterleaks")] = testkit.EnginePath(t, "betterleaks")
	for _, d := range []string{e.home, e.kgHome} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The same wrapper the installer writes: skip quietly if the binary is gone.
	// The value is quoted: an unquoted ";" starts a comment in a git config file.
	hook := func(name, event string) string {
		return fmt.Sprintf("[hook %q]\n\tevent = %s\n\tcommand = \"test -x %s || exit 0; exec %s hook %s\"\n", "keyguard-"+name, event, self, self, event)
	}
	cfg := "[user]\n\tname = Test\n\temail = test@example.com\n[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n" +
		"[advice]\n\tdetachedHead = false\n[pull]\n\trebase = false\n[protocol \"file\"]\n\tallow = always\n" +
		hook("precommit", "pre-commit") + hook("prepush", "pre-push") + hook("reftx", "reference-transaction") + hook("commitmsg", "commit-msg")
	if err := os.WriteFile(e.gitconfig, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

// setKnown registers fakes with the helper's matcher (as NAME=value lines).
func (e *tenv) setKnown(fakes map[string]string) {
	var lines []string
	for n, v := range fakes {
		lines = append(lines, n+"="+v)
	}
	sort.Strings(lines)
	e.extra["KG_TEST_FAKES"] = strings.Join(lines, "\n")
}

// environ is the child environment: the parent's, minus anything git or keyguard would
// read from it, plus this world.
func (e *tenv) environ(more ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "GIT_") || strings.HasPrefix(k, "KEYGUARD_") || strings.HasPrefix(k, "KG_") || k == "HOME" || k == "XDG_CONFIG_HOME" {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "HOME="+e.home, "XDG_CONFIG_HOME="+filepath.Join(e.home, ".config"),
		"GIT_CONFIG_GLOBAL="+e.gitconfig, "GIT_CONFIG_NOSYSTEM=1", "KEYGUARD_HOME="+e.kgHome,
		helperEnv+"=1", "GIT_TERMINAL_PROMPT=0", "GIT_EDITOR=true")
	e.mu.Lock()
	for k, v := range e.extra {
		env = append(env, k+"="+v)
	}
	e.mu.Unlock()
	return append(env, more...)
}

// activate puts this world into the test process's own environment, for tests that call
// the hooks in-process. Such tests cannot run in parallel.
func (e *tenv) activate() {
	e.t.Helper()
	for _, kv := range e.environ() {
		k, v, _ := strings.Cut(kv, "=")
		if k == helperEnv {
			continue // this process is the test, not the helper
		}
		e.t.Setenv(k, v)
	}
}

type result struct {
	out, err string
	code     int
}

func (r result) String() string {
	return fmt.Sprintf("exit %d\nstdout:\n%s\nstderr:\n%s", r.code, r.out, r.err)
}

// run executes a command in dir with this world's environment.
func (e *tenv) run(dir string, stdin string, name string, args ...string) result {
	e.t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = e.environ()
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			e.t.Fatalf("%s %v: %v", name, args, err)
		}
		code = ee.ExitCode()
	}
	return result{out.String(), errb.String(), code}
}

// git runs git in dir; the result is returned whatever the exit code.
func (e *tenv) git(dir string, args ...string) result {
	e.t.Helper()
	return e.run(dir, "", "git", args...)
}

// must runs git and fails the test on a non-zero exit.
func (e *tenv) must(dir string, args ...string) string {
	e.t.Helper()
	r := e.git(dir, args...)
	if r.code != 0 {
		e.t.Fatalf("git %v in %s failed: %s", args, dir, r)
	}
	return strings.TrimSpace(r.out)
}

// noHooks are the config overrides the mirror code uses (PLAN.md invariant 6). Using them
// here also proves git honours them.
var noHooks = []string{"-c", "hook.keyguard-precommit.enabled=false", "-c", "hook.keyguard-prepush.enabled=false",
	"-c", "hook.keyguard-reftx.enabled=false", "-c", "hook.keyguard-commitmsg.enabled=false"}

// mustQuiet runs git with keyguard's hooks switched off, to build history that the hooks
// would (rightly) refuse: the leaked key that is already there when something is fetched.
func (e *tenv) mustQuiet(dir string, args ...string) string {
	e.t.Helper()
	return e.must(dir, append(append([]string{}, noHooks...), args...)...)
}

func (e *tenv) initRepo(name string) string {
	e.t.Helper()
	dir := filepath.Join(e.root, name)
	e.must(e.root, "init", "-q", "-b", "main", dir)
	return dir
}

func (e *tenv) initBare(name string) string {
	e.t.Helper()
	dir := filepath.Join(e.root, name)
	e.must(e.root, "init", "-q", "--bare", "-b", "main", dir)
	return dir
}

func (e *tenv) write(dir, rel, content string) {
	e.t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// commitFile writes a file and commits it with hooks on; it fails the test if blocked.
func (e *tenv) commitFile(dir, rel, content, msg string) string {
	e.t.Helper()
	e.write(dir, rel, content)
	e.must(dir, "add", "--", rel)
	e.must(dir, "commit", "-q", "-m", msg)
	return e.must(dir, "rev-parse", "HEAD")
}

// quietCommit writes a file and commits it with keyguard's hooks switched off.
func (e *tenv) quietCommit(dir, rel, content, msg string) string {
	e.t.Helper()
	e.write(dir, rel, content)
	e.mustQuiet(dir, "add", "--", rel)
	e.mustQuiet(dir, "commit", "-q", "-m", msg)
	return e.must(dir, "rev-parse", "HEAD")
}

// dangling writes a commit that no ref points at: the state `git commit` is in while the
// reference-transaction hook runs, when the object exists and the branch has not moved
// yet. parent may be "" for a root commit. Nothing here updates a ref, so no hook fires.
func (e *tenv) dangling(dir, parent, rel, content, msg string) string {
	e.t.Helper()
	e.extra["GIT_INDEX_FILE"] = filepath.Join(e.root, "dangling-index")
	defer delete(e.extra, "GIT_INDEX_FILE")
	if parent == "" {
		e.must(dir, "read-tree", "--empty")
	} else {
		e.must(dir, "read-tree", parent)
	}
	blob := strings.TrimSpace(e.run(dir, content, "git", "hash-object", "-w", "--stdin").out)
	e.must(dir, "update-index", "--add", "--cacheinfo", "100644,"+blob+","+rel)
	args := []string{"commit-tree", e.must(dir, "write-tree"), "-m", msg}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	return e.must(dir, args...)
}

// hook runs the hook binary directly, as git would, with stdin.
func (e *tenv) hook(dir, name, stdin string, args ...string) result {
	e.t.Helper()
	self, err := os.Executable()
	if err != nil {
		e.t.Fatal(err)
	}
	return e.run(dir, stdin, self, append([]string{"hook", name}, args...)...)
}

const zeroOID = "0000000000000000000000000000000000000000"
