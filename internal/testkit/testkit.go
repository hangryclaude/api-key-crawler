// Package testkit is the one way a keyguard test finds the scanner engines and the real
// mirrors it may read, and the one guard that notices a test run changing an engine binary.
// It imports nothing from keyguard, so every test package can use it.
//
// Why it exists. Tests used to name engine paths of the user's Mac, which fails anywhere else,
// and each package that ran an engine kept its own copy of a size-and-mtime check. A test
// once wrote through a symlink and replaced the real trufflehog with a stub that exits 0, so
// every scan "passed" afterwards. Now a test asks EnginePath, and a package that runs an
// engine ends its TestMain with Main, which hashes every engine before and after the run.
package testkit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Names are the engines keyguard drives.
var Names = []string{"betterleaks", "gitleaks", "trufflehog", "titus"}

// RequireEnv set to "1" makes a missing engine fail its test instead of skipping it. CI sets
// it, so a runner that lost an engine fails loudly instead of passing without running it.
const RequireEnv = "KEYGUARD_TEST_REQUIRE_ENGINES"

// OverrideEnv names the variable that pins an engine: KEYGUARD_TEST_BETTERLEAKS and so on.
func OverrideEnv(name string) string {
	return "KEYGUARD_TEST_" + strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		}
		return '_'
	}, name)
}

// OverrideError is a pin that cannot be used. It is never answered by looking elsewhere: a
// test that thinks it is running engine X must not quietly run engine Y.
type OverrideError struct {
	Var, Value, Why string
}

func (e *OverrideError) Error() string { return fmt.Sprintf("%s=%q: %s", e.Var, e.Value, e.Why) }

// What the test binary saw when it started. A test may t.Setenv a fake HOME or PATH, and the
// real engines and the real mirrors are still where they were.
var (
	startHome = userHome()
	startPath = os.Getenv("PATH")
)

func userHome() string {
	h, _ := os.UserHomeDir()
	return h
}

// candidateDirs are the places an engine lives on this Mac, in the order they are tried
// after PATH, the same order the installer uses to discover them.
func candidateDirs(name, home string) []string {
	dirs := []string{"/opt/homebrew/bin"}
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".local", "bin"))
	}
	dirs = append(dirs, "/usr/local/bin")
	return dirs
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p) // through symlinks: brew's bin entries are links into the Cellar
	return err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0
}

// inDirs returns the first executable called name in dirs. A relative entry is skipped: an
// engine found relative to the working directory would change with the test's cwd.
func inDirs(name string, dirs []string) (string, bool) {
	for _, d := range dirs {
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		if p := filepath.Join(d, name); isExecutable(p) {
			return p, true
		}
	}
	return "", false
}

// LookupEngine finds an engine, in this order: the KEYGUARD_TEST_<NAME> pin (an absolute
// path to an executable file); exec.LookPath; /opt/homebrew/bin, $HOME/.local/bin and
// /usr/local/bin. Where HOME or PATH have been
// changed since the test binary started, the original values are tried after the current ones.
// An unusable pin is an *OverrideError, not a reason to look further.
func LookupEngine(name string) (string, error) {
	if v := os.Getenv(OverrideEnv(name)); v != "" {
		switch {
		case !filepath.IsAbs(v):
			return "", &OverrideError{OverrideEnv(name), v, "not an absolute path"}
		case !isExecutable(v):
			return "", &OverrideError{OverrideEnv(name), v, "not an executable file"}
		}
		return v, nil
	}
	if p, err := exec.LookPath(name); err == nil && filepath.IsAbs(p) && isExecutable(p) {
		return p, nil
	}
	for _, home := range []string{userHome(), startHome} {
		if p, ok := inDirs(name, candidateDirs(name, home)); ok {
			return p, nil
		}
	}
	if p, ok := inDirs(name, filepath.SplitList(startPath)); ok {
		return p, nil
	}
	return "", fmt.Errorf("%s is not installed: pin it with %s, or put it on PATH, in /opt/homebrew/bin, ~/.local/bin or /usr/local/bin",
		name, OverrideEnv(name))
}

// EnginePath is the path of an engine for a test. When the engine is missing the test is
// skipped, or failed when KEYGUARD_TEST_REQUIRE_ENGINES=1. A pin that cannot be used fails the
// test either way.
func EnginePath(tb testing.TB, name string) string {
	tb.Helper()
	p, err := LookupEngine(name)
	if err == nil {
		return p
	}
	var oe *OverrideError
	if errors.As(err, &oe) {
		tb.Fatalf("testkit: %v", err)
	}
	if os.Getenv(RequireEnv) == "1" {
		tb.Fatalf("testkit: %v (%s=1, so this is a failure, not a skip)", err, RequireEnv)
	}
	tb.Skipf("testkit: %v", err)
	return ""
}

// LookupMirror finds keyguard's bare mirror of github.com/<owner>/<name> under
// $HOME/.keyguard/cache/mirrors, where HOME is the real one even if a test changed it.
func LookupMirror(owner, name string) (string, bool) {
	name = strings.TrimSuffix(name, ".git")
	if startHome == "" || !singleElement(owner) || !singleElement(name) {
		return "", false
	}
	p := filepath.Join(startHome, ".keyguard", "cache", "mirrors", "github.com", owner, name+".git")
	if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
		return "", false
	}
	return p, true
}

func singleElement(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `/\`) && !strings.ContainsRune(s, 0)
}

// RealMirror is the path of a real mirror, for a test that reads one. It is read-only ground:
// the test must leave it exactly as it found it. The test is skipped where the mirror is
// absent, which is every machine but the user's, CI included.
func RealMirror(tb testing.TB, owner, name string) string {
	tb.Helper()
	if !singleElement(owner) || !singleElement(strings.TrimSuffix(name, ".git")) {
		tb.Fatalf("testkit: %q/%q is not a mirror name", owner, name)
	}
	p, ok := LookupMirror(owner, name)
	if !ok {
		tb.Skipf("testkit: no real mirror of %s/%s here", owner, name)
	}
	return p
}

// engineFile is one engine as Main saw it: where it was found, the file behind that path,
// and the content hash.
type engineFile struct {
	name, path, real, sum string
}

func (e engineFile) String() string {
	if e.real == e.path {
		return e.name + " " + e.path
	}
	return e.name + " " + e.path + " (-> " + e.real + ")"
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// snapshot hashes every engine this machine has, once per file behind the paths found.
func snapshot() ([]engineFile, error) {
	var found []engineFile
	seen := map[string]bool{}
	for _, name := range Names {
		p, err := LookupEngine(name)
		var oe *OverrideError
		if errors.As(err, &oe) {
			return nil, err
		}
		if err != nil {
			continue // not installed: nothing to protect
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if seen[real] {
			continue
		}
		seen[real] = true
		found = append(found, engineFile{name: name, path: p, real: real})
	}
	var wg sync.WaitGroup
	errs := make([]error, len(found))
	for i := range found {
		wg.Go(func() { found[i].sum, errs[i] = hashFile(found[i].real) })
	}
	wg.Wait()
	return found, errors.Join(errs...)
}

const prefixLen = 16

func prefix(sum string) string {
	if sum == "" {
		return "missing"
	}
	return sum[:prefixLen]
}

// changes names every engine that is not what it was: other content, another file behind the
// same path, or gone. It re-reads the path rather than trusting the earlier resolution, so a
// symlink retargeted during the run shows.
func changes(before []engineFile) []string {
	var out []string
	for _, e := range before {
		real, err := filepath.EvalSymlinks(e.path)
		if err != nil {
			out = append(out, fmt.Sprintf("%s: gone (was sha256 %s)", e, prefix(e.sum)))
			continue
		}
		sum, err := hashFile(real)
		if err != nil {
			sum = ""
		}
		switch {
		case sum != e.sum:
			out = append(out, fmt.Sprintf("%s: sha256 %s -> %s", e, prefix(e.sum), prefix(sum)))
		case real != e.real:
			out = append(out, fmt.Sprintf("%s: now points at %s (same content, sha256 %s)", e, real, prefix(sum)))
		}
	}
	return out
}

// runner is what Run drives; *testing.M is one.
type runner interface{ Run() int }

// Run is m.Run guarded: it hashes every engine before the tests and after, and if any
// differs it reports the file and both hash prefixes on stderr and returns 1. Packages that
// need setup and teardown around the tests call it where they would call m.Run:
//
//	code := testkit.Run(m)
//	cleanup()
//	os.Exit(code)
//
// A pin in KEYGUARD_TEST_<NAME> that cannot be used stops the run with exit code 2.
func Run(m *testing.M) int { return run(m) }

func run(r runner) int {
	before, err := snapshot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "testkit: cannot read the engines before the tests: %v\n", err)
		return 2
	}
	code := r.Run()
	if diff := changes(before); len(diff) > 0 {
		fmt.Fprintln(os.Stderr, "testkit: FAIL: the tests changed an engine binary. Engines are read-only; a test must never write to or through one.")
		for _, d := range diff {
			fmt.Fprintln(os.Stderr, "testkit:   "+d)
		}
		return 1
	}
	return code
}

// Main is a whole TestMain for a package whose tests run an engine:
//
//	func TestMain(m *testing.M) { testkit.Main(m) }
func Main(m *testing.M) { os.Exit(Run(m)) }
