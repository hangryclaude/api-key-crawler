package install

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/engines"
	"keyguard/internal/inventory/ghcli"
	"keyguard/internal/testkit"
)

// The doctor and install tests probe the real engines. A test once wrote through a symlink and
// replaced the real trufflehog; testkit hashes every engine before and after the suite.
func TestMain(m *testing.M) { testkit.Main(m) }

// world is a throwaway machine: a home, a global git config, a LaunchAgents dir and a
// keyguard root, all under one temp dir. Nothing in a test can reach the real ones.
type world struct {
	t         testing.TB
	dir       string
	home      string
	gitconfig string
	launch    string
	paths     core.Paths
	exe       string
	run       *fakeRun
	probe     func(name, path string, pin *Pin) (string, error)
	clock     time.Time
	fakebin   string // the four engines every test machine has, first on PATH
	origPath  string // PATH as the suite was started with, for the tests about the real engines
}

// newWorld builds the machine. The executable to install is a one-line shell script: the
// installer copies bytes and never runs it.
func newWorld(t testing.TB) *world {
	t.Helper()
	dir := t.TempDir()
	w := &world{
		t: t, dir: dir,
		home:      filepath.Join(dir, "home"),
		gitconfig: filepath.Join(dir, "gitconfig"),
		launch:    filepath.Join(dir, "LaunchAgents"),
		exe:       filepath.Join(dir, "build", "keyguard"),
		clock:     time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC),
	}
	w.paths = core.PathsAt(filepath.Join(w.home, ".keyguard"))
	for _, d := range []string{w.home, filepath.Dir(w.exe)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	w.setExe("#!/bin/sh\necho keyguard-test-binary\n")
	w.run = &fakeRun{loaded: map[string]bool{}}
	w.probe = RealProbe
	// The real environment must not leak into anything the code under test does.
	t.Setenv("HOME", w.home)
	t.Setenv("KEYGUARD_HOME", "")
	t.Setenv("GIT_CONFIG_GLOBAL", w.gitconfig)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	w.fakeEngines()
	return w
}

// fakeEngines puts four tiny engines in front of the real ones on PATH, so that install finds,
// copies, pins and starts them like any engine and the suite neither depends on the Mac it runs
// on nor copies a 170 MB trufflehog for every install. They answer "version", and betterleaks
// also answers "config check" with the rule counts the doctor compares. A test about the real
// binaries puts the real PATH back.
func (w *world) fakeEngines() {
	w.t.Helper()
	w.origPath = os.Getenv("PATH")
	w.fakebin = filepath.Join(w.dir, "fakebin")
	if err := os.MkdirAll(w.fakebin, 0o755); err != nil {
		w.t.Fatal(err)
	}
	for _, name := range engines.Names {
		script := "#!/bin/sh\ncase \"$*\" in\n" +
			"  *\"config check -c\"*) echo 'OK: 475 rules (218 with validation, 257 without validation)';;\n" +
			"  *\"config check\"*) echo 'OK: 463 rules (218 with validation, 245 without validation)';;\n" +
			"  *) echo '" + name + " version 9.9.9';;\nesac\n"
		path := filepath.Join(w.fakebin, name)
		if _, err := os.Lstat(path); err == nil {
			w.t.Fatalf("%s already exists; a test must not write over something it did not make", path)
		}
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			w.t.Fatal(err)
		}
	}
	w.t.Setenv("PATH", w.fakebin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func (w *world) setExe(body string) {
	w.t.Helper()
	if err := os.WriteFile(w.exe, []byte(body), 0o755); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) opts() Options {
	return Options{
		Paths: w.paths, Home: w.home, GitConfig: w.gitconfig, LaunchDir: w.launch, Executable: w.exe,
		UID: 501, Run: w.run.run, Now: func() time.Time { w.clock = w.clock.Add(time.Second); return w.clock },
		// The engines are the four tiny ones on PATH, so the real copy and the real pin run in
		// every install. titus is in no default tier, so there is no rule cache to build.
		NoPrewarm: true,
	}
}

func (w *world) install(mod ...func(*Options)) *Result {
	w.t.Helper()
	o := w.opts()
	for _, m := range mod {
		m(&o)
	}
	res, err := Install(context.Background(), o)
	if err != nil {
		w.t.Fatalf("Install: %v\nactions: %+v", err, res)
	}
	return res
}

func (w *world) uninstall(mod ...func(*Options)) *Result {
	w.t.Helper()
	o := w.opts()
	for _, m := range mod {
		m(&o)
	}
	res, err := Uninstall(context.Background(), o)
	if err != nil {
		w.t.Fatalf("Uninstall: %v", err)
	}
	return res
}

func (w *world) writeGitConfig(body string) {
	w.t.Helper()
	if err := os.WriteFile(w.gitconfig, []byte(body), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) gitConfigBytes() []byte {
	b, err := os.ReadFile(w.gitconfig)
	if err != nil {
		return nil
	}
	return b
}

// fakeRun runs git for real and plays launchd: the real launchctl would load jobs into the
// session of whoever runs the tests. Its gh is logged in to two accounts, and the active one
// is in two orgs, unless loggedOut is set.
type fakeRun struct {
	loggedOut     bool
	mu            sync.Mutex
	calls         []string
	loaded        map[string]bool
	failBootstrap error
}

func (f *fakeRun) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "gh" {
		switch {
		case f.loggedOut:
			return nil, errors.New("exit status 1")
		case slices.Equal(args, ghcli.AuthStatusArgs):
			return []byte("hangryclaude\nalt-builds\n"), nil
		case slices.Equal(args, ghcli.OrgsArgs):
			return []byte("Loony-Labs-Video\nacme-apps\n"), nil
		}
		return []byte("placeholder-not-a-token\n"), nil
	}
	if name != "launchctl" {
		return ExecRunner(ctx, name, args...)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.Join(args, " "))
	label := func(s string) string { return strings.TrimSuffix(filepath.Base(s), ".plist") }
	switch args[0] {
	case "print":
		if f.loaded[label(args[1])] {
			return []byte("state = running\n"), nil
		}
		return nil, errors.New("Could not find service")
	case "bootstrap":
		if f.failBootstrap != nil {
			return nil, f.failBootstrap
		}
		f.loaded[label(args[2])] = true
	case "bootout":
		if !f.loaded[label(args[1])] {
			return nil, errors.New("No such process")
		}
		delete(f.loaded, label(args[1]))
	}
	return nil, nil
}

func (f *fakeRun) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (f *fakeRun) reset() { f.mu.Lock(); f.calls = nil; f.mu.Unlock() }

func (f *fakeRun) isLoaded(label string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loaded[label]
}

// tree lists every file under dir with its content hash, so a test can say "nothing changed".
func tree(t testing.TB, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			out[rel+"/"] = "dir"
			return nil
		}
		sum, _ := hashFile(p)
		out[rel] = sum
		return nil
	})
	return out
}

func diffTrees(a, b map[string]string) string {
	var diffs []string
	for k, v := range a {
		if w, ok := b[k]; !ok {
			diffs = append(diffs, "removed "+k)
		} else if w != v {
			diffs = append(diffs, "changed "+k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			diffs = append(diffs, "added "+k)
		}
	}
	sort.Strings(diffs)
	return strings.Join(diffs, "\n")
}

func gitOut(t testing.TB, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, errb.String())
	}
	return strings.TrimSpace(out.String())
}

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

func mustf(t testing.TB, err error, format string, a ...any) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", fmt.Sprintf(format, a...), err)
	}
}

func coreAt(root string) core.Paths { return core.PathsAt(root) }
