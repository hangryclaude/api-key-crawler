package testkit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The package's own tests run under the guard they test: the real engines on this machine are
// hashed before and after, so a bug here that touched one would fail the run.
func TestMain(m *testing.M) { Main(m) }

// recorder stands in for the *testing.T an EnginePath caller has, to see whether it skipped or
// failed. Embedding the interface supplies the methods a fake cannot (they are unexported).
type recorder struct {
	testing.TB
	skipped, failed string
}

type stopped struct{}

func (r *recorder) Helper() {}
func (r *recorder) Skipf(f string, a ...any) {
	r.skipped = fmt.Sprintf(f, a...)
	panic(stopped{})
}
func (r *recorder) Fatalf(f string, a ...any) {
	r.failed = fmt.Sprintf(f, a...)
	panic(stopped{})
}

// observe runs fn against a recorder, the way a test body would stop at Skip or Fatal.
func observe(t *testing.T, fn func(testing.TB)) *recorder {
	t.Helper()
	r := &recorder{TB: t}
	func() {
		defer func() {
			if v := recover(); v != nil && v != (stopped{}) {
				panic(v)
			}
		}()
		fn(r)
	}()
	return r
}

// found calls EnginePath the way a test body would, and fails this test if the engine is not
// found. Called with the real t, a miss would only skip the test, and a skipped test passes: a
// broken search would then hide behind its own tests.
func found(t *testing.T, name string) string {
	t.Helper()
	var p string
	if r := observe(t, func(tb testing.TB) { p = EnginePath(tb, name) }); r.skipped != "" || r.failed != "" {
		t.Fatalf("EnginePath(%q) found nothing: skipped=%q failed=%q", name, r.skipped, r.failed)
	}
	return p
}

// fake writes an executable file under dir. Content differs per name so no two hash alike.
func fake(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n# fake "+name+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func sum(b string) string {
	h := sha256.Sum256([]byte(b))
	return hex.EncodeToString(h[:])
}

// unique returns an engine name no machine has installed.
func unique(t *testing.T) string {
	t.Helper()
	return "kgtest-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))
}

func TestOverrideEnvNames(t *testing.T) {
	for name, want := range map[string]string{
		"betterleaks": "KEYGUARD_TEST_BETTERLEAKS", "gitleaks": "KEYGUARD_TEST_GITLEAKS",
		"trufflehog": "KEYGUARD_TEST_TRUFFLEHOG", "titus": "KEYGUARD_TEST_TITUS", "cal-com.v2": "KEYGUARD_TEST_CAL_COM_V2",
	} {
		if got := OverrideEnv(name); got != want {
			t.Errorf("OverrideEnv(%q) = %q, want %q", name, got, want)
		}
	}
	if !slices.Equal(Names, []string{"betterleaks", "gitleaks", "trufflehog", "titus"}) {
		t.Errorf("engine names: %v", Names)
	}
}

func TestCandidateDirsAreInTheDocumentedOrder(t *testing.T) {
	// Spelled in pieces so no test file names an engine directory as a literal path.
	root := string(filepath.Separator)
	brew, local := root+filepath.Join("opt", "homebrew", "bin"), root+filepath.Join("usr", "local", "bin")
	home := root + "h"
	userBin := filepath.Join(home, ".local", "bin")
	want := []string{brew, userBin, local}
	for _, name := range []string{"betterleaks", "gitleaks", "trufflehog", "titus", "anything"} {
		if got := candidateDirs(name, home); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	if got := candidateDirs("gitleaks", ""); !slices.Equal(got, []string{brew, local}) {
		t.Errorf("no home must not produce relative dirs: %v", got)
	}
}

func TestInDirsTakesTheFirstExecutableAndSkipsRelativeEntries(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	if _, ok := inDirs("tool", []string{a, b}); ok {
		t.Fatal("found a tool nobody made")
	}
	fake(t, b, "tool")
	if p, ok := inDirs("tool", []string{a, b}); !ok || p != filepath.Join(b, "tool") {
		t.Fatalf("got %q %v", p, ok)
	}
	fake(t, a, "tool")
	if p, _ := inDirs("tool", []string{a, b}); p != filepath.Join(a, "tool") {
		t.Fatalf("the first directory must win, got %q", p)
	}
	// A file without the execute bit is not an engine, and a directory is not either.
	c := t.TempDir()
	if err := os.WriteFile(filepath.Join(c, "plain"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(c, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"plain", "dir"} {
		if _, ok := inDirs(n, []string{c}); ok {
			t.Errorf("%s accepted as an engine", n)
		}
	}
	// Relative and empty PATH entries mean "wherever the test happens to run": never searched.
	t.Chdir(a)
	if _, ok := inDirs("tool", []string{"", ".", "../" + filepath.Base(a)}); ok {
		t.Error("a relative directory was searched")
	}
}

func TestEnginePathPinBeatsPATH(t *testing.T) {
	name := unique(t)
	pinDir, pathDir := t.TempDir(), t.TempDir()
	pinned, onPath := fake(t, pinDir, name), fake(t, pathDir, name)
	t.Setenv("PATH", pathDir)

	t.Setenv(OverrideEnv(name), "")
	if got := found(t, name); got != onPath {
		t.Fatalf("without a pin PATH answers: got %q, want %q", got, onPath)
	}
	t.Setenv(OverrideEnv(name), pinned)
	if got := found(t, name); got != pinned {
		t.Fatalf("the pin must win: got %q, want %q", got, pinned)
	}
}

func TestEnginePathFindsHomeLocalBinWhenPATHHasNothing(t *testing.T) {
	name := unique(t)
	home := t.TempDir()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	want := fake(t, bin, name)
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	t.Setenv(OverrideEnv(name), "")
	if got := found(t, name); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// PATH outranks the home directory.
	pathDir := t.TempDir()
	onPath := fake(t, pathDir, name)
	t.Setenv("PATH", pathDir)
	if got := found(t, name); got != onPath {
		t.Fatalf("PATH must come first: got %q, want %q", got, onPath)
	}
}

// A test may point HOME at a fake machine; the engines are still where they were.
func TestEnginePathRemembersTheRealHome(t *testing.T) {
	name := unique(t)
	real := t.TempDir()
	bin := filepath.Join(real, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	want := fake(t, bin, name)
	old := startHome
	startHome = real
	t.Cleanup(func() { startHome = old })

	t.Setenv("HOME", t.TempDir()) // the test's fake home has no engines
	t.Setenv("PATH", t.TempDir())
	t.Setenv(OverrideEnv(name), "")
	if got := found(t, name); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMissingEngineSkipsLocallyAndFailsInCI(t *testing.T) {
	name := unique(t)
	t.Setenv("PATH", t.TempDir())
	t.Setenv(OverrideEnv(name), "")

	t.Setenv(RequireEnv, "")
	r := observe(t, func(tb testing.TB) { EnginePath(tb, name) })
	if r.skipped == "" || r.failed != "" || !strings.Contains(r.skipped, OverrideEnv(name)) {
		t.Fatalf("locally a missing engine skips and says how to pin it: skipped=%q failed=%q", r.skipped, r.failed)
	}

	t.Setenv(RequireEnv, "1")
	r = observe(t, func(tb testing.TB) { EnginePath(tb, name) })
	if r.failed == "" || r.skipped != "" || !strings.Contains(r.failed, RequireEnv) {
		t.Fatalf("with %s=1 a missing engine fails: skipped=%q failed=%q", RequireEnv, r.skipped, r.failed)
	}

	// Only "1" turns it on, so a stray empty or "0" cannot fail a developer's run.
	for _, v := range []string{"0", "true", "yes"} {
		t.Setenv(RequireEnv, v)
		if r := observe(t, func(tb testing.TB) { EnginePath(tb, name) }); r.skipped == "" {
			t.Errorf("%s=%s should not require engines", RequireEnv, v)
		}
	}
}

func TestAPinThatCannotBeUsedIsNeverAnsweredByLookingElsewhere(t *testing.T) {
	name := unique(t)
	dir := t.TempDir()
	fake(t, dir, name) // something on PATH that a lenient lookup would settle for
	t.Setenv("PATH", dir)
	notExec := filepath.Join(dir, "plain")
	if err := os.WriteFile(notExec, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for why, pin := range map[string]string{
		"relative": "bin/" + name, "missing": filepath.Join(dir, "nope"), "not executable": notExec, "a directory": dir,
	} {
		t.Setenv(OverrideEnv(name), pin)
		_, err := LookupEngine(name)
		var oe *OverrideError
		if !errors.As(err, &oe) || oe.Var != OverrideEnv(name) {
			t.Errorf("%s: %v", why, err)
		}
		// Not a skip, even without REQUIRE: a typo'd pin must not hide a test.
		t.Setenv(RequireEnv, "")
		if r := observe(t, func(tb testing.TB) { EnginePath(tb, name) }); r.failed == "" || r.skipped != "" {
			t.Errorf("%s: skipped=%q failed=%q", why, r.skipped, r.failed)
		}
	}
}

func TestRealMirror(t *testing.T) {
	home := t.TempDir()
	mirror := filepath.Join(home, ".keyguard", "cache", "mirrors", "github.com", "someone", "repo.git")
	if err := os.MkdirAll(mirror, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(mirror), "afile.git"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := startHome
	startHome = home
	t.Cleanup(func() { startHome = old })
	t.Setenv("HOME", t.TempDir()) // the real home is the one the binary started with

	for _, name := range []string{"repo", "repo.git"} {
		var got string
		if r := observe(t, func(tb testing.TB) { got = RealMirror(tb, "someone", name) }); r.skipped != "" || r.failed != "" {
			t.Fatalf("RealMirror(%q) found nothing: skipped=%q failed=%q", name, r.skipped, r.failed)
		}
		if got != mirror {
			t.Errorf("RealMirror(%q) = %q, want %q", name, got, mirror)
		}
	}
	if r := observe(t, func(tb testing.TB) { RealMirror(tb, "someone", "absent") }); r.skipped == "" || r.failed != "" {
		t.Errorf("an absent mirror skips: skipped=%q failed=%q", r.skipped, r.failed)
	}
	if r := observe(t, func(tb testing.TB) { RealMirror(tb, "someone", "afile") }); r.skipped == "" {
		t.Error("a file is not a mirror")
	}
	for _, bad := range [][2]string{{"..", "repo"}, {"someone", "../repo"}, {"a/b", "repo"}, {"", "repo"}, {"someone", ""}, {"someone", ".."}} {
		if r := observe(t, func(tb testing.TB) { RealMirror(tb, bad[0], bad[1]) }); r.failed == "" {
			t.Errorf("RealMirror(%q, %q) should be refused", bad[0], bad[1])
		}
		if _, ok := LookupMirror(bad[0], bad[1]); ok {
			t.Errorf("LookupMirror(%q, %q) found something", bad[0], bad[1])
		}
	}
	if _, ok := LookupMirror("someone", "repo"); !ok {
		t.Error("LookupMirror missed a mirror that exists")
	}
}

// pinAll points all four engines at fakes under dir and returns their paths by name.
func pinAll(t *testing.T, dir string) map[string]string {
	t.Helper()
	paths := map[string]string{}
	for _, n := range Names {
		paths[n] = fake(t, dir, n)
		t.Setenv(OverrideEnv(n), paths[n])
	}
	return paths
}

func TestSnapshotHashesEachFileOnceThroughSymlinks(t *testing.T) {
	dir := t.TempDir()
	paths := pinAll(t, dir)
	// betterleaks is a link to trufflehog's file: one file, listed once.
	if err := os.Remove(paths["betterleaks"]); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(paths["trufflehog"], paths["betterleaks"]); err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap) != 3 {
		t.Fatalf("%d entries, want 3 (the link and its target are one file): %v", len(snap), snap)
	}
	for _, e := range snap {
		b, _ := os.ReadFile(e.real)
		if e.sum != sum(string(b)) {
			t.Errorf("%s: wrong hash", e)
		}
	}
	if d := changes(snap); len(d) != 0 {
		t.Fatalf("nothing changed, yet: %v", d)
	}
}

func TestChangesNamesTheFileAndBothHashes(t *testing.T) {
	dir := t.TempDir()
	paths := pinAll(t, dir)
	before, err := snapshot()
	if err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(paths["titus"])
	if err := os.WriteFile(paths["titus"], append(orig, "# more\n"...), 0o755); err != nil {
		t.Fatal(err)
	}
	d := changes(before)
	if len(d) != 1 || !strings.Contains(d[0], paths["titus"]) ||
		!strings.Contains(d[0], "sha256 "+sum(string(orig))[:16]+" -> "+sum(string(orig) + "# more\n")[:16]) {
		t.Fatalf("changes = %q", d)
	}
}

// fakeRun is a test run that leaves the engines alone or doesn't.
type fakeRun struct {
	code int
	do   func()
}

func (f fakeRun) Run() int {
	if f.do != nil {
		f.do()
	}
	return f.code
}

func TestRunKeepsTheTestResultWhenNothingChanged(t *testing.T) {
	pinAll(t, t.TempDir())
	for _, code := range []int{0, 1, 2} {
		if got := run(fakeRun{code: code}); got != code {
			t.Errorf("run returned %d, want the tests' own %d", got, code)
		}
	}
}

func TestRunFailsWhenARunChangesAnEngine(t *testing.T) {
	paths := pinAll(t, t.TempDir())
	got := run(fakeRun{code: 0, do: func() {
		if err := os.WriteFile(paths["gitleaks"], []byte("#!/bin/sh\necho stub\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}})
	if got != 1 {
		t.Fatalf("run = %d, want 1", got)
	}
}

// ---- Main, observed from outside --------------------------------------------------------
//
// Main ends in os.Exit, so these tests start the test binary again (the os/exec helper-process
// pattern) with every engine pinned to a throwaway fake. The child's TestMain is the real
// Main; its one test, TestHelperProcess, changes a fake in the way the mode says; and the
// exit code and stderr are read here.

const (
	modeEnv   = "KG_TESTKIT_CHILD_MODE"
	targetEnv = "KG_TESTKIT_CHILD_TARGET"
	otherEnv  = "KG_TESTKIT_CHILD_OTHER"
)

const (
	appendedText = "\n# appended by the child\n"
	stubText     = "#!/bin/sh\necho stub\n"
	replacedText = "#!/bin/sh\necho replaced\n"
)

// mustBeScratch refuses a target that is not, all the way through any symlinks, a file in the
// system temp dir. The child writes to files, and this package exists because a test once
// wrote through a link to a real engine; a wrong env var must not be able to do that again.
func mustBeScratch(t *testing.T, p string) {
	t.Helper()
	tmp, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil || !strings.HasPrefix(real, tmp+string(filepath.Separator)) {
		t.Fatalf("refusing to touch %q (resolves to %q): not under %s", p, real, tmp)
	}
}

// TestHelperProcess is the body of the child processes below. In an ordinary run no mode is
// set and it does nothing.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv(modeEnv)
	if mode == "" {
		return
	}
	target := os.Getenv(targetEnv)
	mustBeScratch(t, target)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	switch mode {
	case "none":
	case "append":
		f, err := os.OpenFile(target, os.O_APPEND|os.O_WRONLY, 0)
		check(err)
		_, err = f.WriteString(appendedText)
		check(err)
		check(f.Close())
	case "identical": // rewritten with the very same bytes: a new mtime, the same file
		b, err := os.ReadFile(target)
		check(err)
		check(os.WriteFile(target, b, 0o755))
	case "replace": // a new file renamed over the old one: the shape of an installer
		check(os.WriteFile(target+".new", []byte(replacedText), 0o755))
		check(os.Rename(target+".new", target))
	case "delete":
		check(os.Remove(target))
	case "through-link": // the incident: a write through a symlink changes the file behind it
		check(os.WriteFile(target, []byte(stubText), 0o755))
	case "retarget":
		check(os.Remove(target))
		check(os.Symlink(os.Getenv(otherEnv), target))
	default:
		t.Fatalf("unknown mode %q", mode)
	}
}

type child struct {
	code   int
	stderr string
}

// startChild runs the test binary again as the helper process.
func startChild(t *testing.T, mode, target, other string, pins map[string]string) child {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), modeEnv+"="+mode, targetEnv+"="+target, otherEnv+"="+other)
	for n, p := range pins {
		cmd.Env = append(cmd.Env, OverrideEnv(n)+"="+p)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return child{0, stderr.String()}
	case errors.As(err, &ee):
		return child{ee.ExitCode(), stderr.String()}
	}
	t.Fatalf("could not start the helper process: %v", err)
	return child{}
}

var changedLine = regexp.MustCompile(`sha256 ([0-9a-f]{16}) -> ([0-9a-f]{16})`)

func TestMainExitsNonZeroWhenARunChangesAnEngine(t *testing.T) {
	const original = "#!/bin/sh\n# fake betterleaks\n"
	cases := []struct {
		mode      string
		linked    bool   // the pinned path is a symlink to the file that holds the content
		wantAfter string // the new content, when the mode makes it known
		wantGone  bool
	}{
		{mode: "append", wantAfter: original + appendedText},
		{mode: "replace", wantAfter: replacedText},
		{mode: "through-link", linked: true, wantAfter: stubText},
		{mode: "delete", wantGone: true},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			dir := t.TempDir()
			pins := pinAll(t, dir)
			target := pins["betterleaks"]
			if c.linked {
				// pins["betterleaks"] becomes a link to the real file.
				realFile := filepath.Join(dir, "kgtest-victim-real")
				if err := os.Rename(target, realFile); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(realFile, target); err != nil {
					t.Fatal(err)
				}
			}
			got := startChild(t, c.mode, target, "", pins)
			if got.code != 1 {
				t.Fatalf("exit code %d, want 1\n%s", got.code, got.stderr)
			}
			if !strings.Contains(got.stderr, target) && !strings.Contains(got.stderr, dir) {
				t.Errorf("stderr does not name the file:\n%s", got.stderr)
			}
			if c.wantGone {
				if !strings.Contains(got.stderr, "gone (was sha256 "+sum(original)[:16]+")") {
					t.Errorf("stderr does not say the file is gone, with its hash:\n%s", got.stderr)
				}
				return
			}
			m := changedLine.FindStringSubmatch(got.stderr)
			if m == nil {
				t.Fatalf("stderr has no 'sha256 <before> -> <after>':\n%s", got.stderr)
			}
			if m[1] != sum(original)[:16] || m[2] != sum(c.wantAfter)[:16] || m[1] == m[2] {
				t.Errorf("hash prefixes %s -> %s, want %s -> %s", m[1], m[2], sum(original)[:16], sum(c.wantAfter)[:16])
			}
			// Only the engine that changed is named.
			for _, n := range []string{"gitleaks", "trufflehog", "titus"} {
				if strings.Contains(got.stderr, filepath.Join(dir, n)) {
					t.Errorf("%s did not change but is named:\n%s", n, got.stderr)
				}
			}
		})
	}
}

func TestMainNoticesASymlinkRetargetedToOtherContent(t *testing.T) {
	dir := t.TempDir()
	pins := pinAll(t, dir)
	link := filepath.Join(dir, "betterleaks-link")
	if err := os.Symlink(pins["betterleaks"], link); err != nil {
		t.Fatal(err)
	}
	pins["betterleaks"] = link
	other := fake(t, dir, "kgtest-victim-other")
	got := startChild(t, "retarget", link, other, pins)
	if got.code != 1 {
		t.Fatalf("exit code %d, want 1\n%s", got.code, got.stderr)
	}
	otherBytes, _ := os.ReadFile(other)
	m := changedLine.FindStringSubmatch(got.stderr)
	if m == nil || m[2] != sum(string(otherBytes))[:16] {
		t.Fatalf("stderr should show the hash of what the link points at now:\n%s", got.stderr)
	}
}

func TestMainNoticesASymlinkRetargetedToIdenticalContent(t *testing.T) {
	dir := t.TempDir()
	pins := pinAll(t, dir)
	link := filepath.Join(dir, "betterleaks-link")
	if err := os.Symlink(pins["betterleaks"], link); err != nil {
		t.Fatal(err)
	}
	pins["betterleaks"] = link
	twin := filepath.Join(dir, "kgtest-victim-twin")
	b, _ := os.ReadFile(link)
	if err := os.WriteFile(twin, b, 0o755); err != nil {
		t.Fatal(err)
	}
	got := startChild(t, "retarget", link, twin, pins)
	if got.code != 1 || !strings.Contains(got.stderr, "now points at") {
		t.Fatalf("exit %d, want 1 with a retarget note:\n%s", got.code, got.stderr)
	}
}

func TestMainPassesWhenNothingChanged(t *testing.T) {
	for _, mode := range []string{"none", "identical"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			pins := pinAll(t, dir)
			got := startChild(t, mode, pins["betterleaks"], "", pins)
			if got.code != 0 || strings.Contains(got.stderr, "testkit:") {
				t.Fatalf("exit %d with stderr:\n%s", got.code, got.stderr)
			}
		})
	}
}

func TestMainStopsAtOnceOnAPinItCannotUse(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for why, pin := range map[string]string{"relative": "bin/betterleaks", "missing": filepath.Join(dir, "nope"), "not executable": plain} {
		pins := pinAll(t, dir)
		pins["trufflehog"] = pin
		got := startChild(t, "none", pins["betterleaks"], "", pins)
		if got.code != 2 || !strings.Contains(got.stderr, "KEYGUARD_TEST_TRUFFLEHOG") {
			t.Errorf("%s: exit %d, stderr:\n%s", why, got.code, got.stderr)
		}
	}
}

// BenchmarkGuardTheRealEngines is what Main adds to a package's test run: every engine this
// machine has, hashed before and again after.
func BenchmarkGuardTheRealEngines(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		before, err := snapshot()
		if err != nil {
			b.Fatal(err)
		}
		if d := changes(before); len(d) != 0 {
			b.Fatal(d)
		}
	}
}
