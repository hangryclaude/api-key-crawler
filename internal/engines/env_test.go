package engines

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"keyguard/internal/core"
)

// emptyTree is the id git gives the tree with nothing in it. As GIT_ATTR_SOURCE it makes git
// read no .gitattributes at all.
func emptyTree(t *testing.T) string {
	t.Helper()
	return gitIn(t.TempDir(), nil, "hash-object", "-t", "tree", "/dev/null")
}

// scanEverything starts name once per mode it has, against a small repo, and returns the calls.
func scanEverything(t *testing.T, name string, o core.ScanOpts) (calls []call, wt string) {
	t.Helper()
	f := getFixture(t)
	e, read := recordingEngine(t, name, f.kr, emptyReport(name), "", 0)
	wt = worktree(t)
	writeLines(t, wt, "a.txt", "line1", "line2", "more")
	gitIn(wt, nil, "add", "-A")
	if name == "betterleaks" || name == "gitleaks" {
		if err := e.ScanStaged(context.Background(), wt, o, func(core.Hit) {}); err != nil {
			t.Fatalf("%s ScanStaged: %v", name, err)
		}
	}
	if err := e.ScanGit(context.Background(), wt, core.Range{All: true}, o, func(core.Hit) {}); err != nil {
		t.Fatalf("%s ScanGit: %v", name, err)
	}
	if err := e.ScanDir(context.Background(), wt, o, func(core.Hit) {}); err != nil {
		t.Fatalf("%s ScanDir: %v", name, err)
	}
	return read(), wt
}

// ----- P0-04: the environment an engine runs in -----

func TestEngineChildEnvironment(t *testing.T) {
	root := os.Getenv("KEYGUARD_HOME")
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			calls, wt := scanEverything(t, name, testOpts())
			if len(calls) == 0 {
				t.Fatal("the engine never started")
			}
			for _, c := range calls {
				// TMPDIR is a directory under the keyguard data root, 0700, not the system's.
				if want := filepath.Join(root, "tmp") + string(filepath.Separator); !strings.HasPrefix(c.env["TMPDIR"], want) {
					t.Errorf("TMPDIR %q is not under %s", c.env["TMPDIR"], want)
				}
				// The user's git configuration, and its hooks, never run inside an engine's git.
				if c.env["GIT_CONFIG_GLOBAL"] != "/dev/null" || c.env["GIT_CONFIG_NOSYSTEM"] != "1" {
					t.Errorf("git configuration is not shut out: %v", c.env)
				}
				// A refs/replace entry can hide a leaking commit from the diff an engine reads.
				if c.env["GIT_NO_REPLACE_OBJECTS"] != "1" {
					t.Errorf("GIT_NO_REPLACE_OBJECTS is not set: %v", c.env)
				}
				if c.env["GOMAXPROCS"] != "2" {
					t.Errorf("GOMAXPROCS %q, want 2 (eight engines run at once)", c.env["GOMAXPROCS"])
				}
				// The scanned repository is not the engine's working directory.
				if strings.HasPrefix(c.cwd, resolved(t, wt)) {
					t.Errorf("engine ran inside the scanned repository: %s", c.cwd)
				}
			}
		})
	}
}

func resolved(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ----- P0-07: threads -----

func TestThreadKnob(t *testing.T) {
	f := getFixture(t)
	gitArgs := func(name string, o core.ScanOpts) call {
		e, read := recordingEngine(t, name, f.kr, emptyReport(name), "", 0)
		if err := e.ScanGit(context.Background(), f.mirror, core.Range{All: true}, o, func(core.Hit) {}); err != nil {
			t.Fatal(err)
		}
		cs := read()
		if len(cs) == 0 {
			t.Fatalf("%s never started", name)
		}
		return cs[0]
	}
	o := testOpts()

	// Pooled: eight engines at once, so each takes two threads and starts no worker pool of its own.
	bl := gitArgs("betterleaks", o)
	if bl.env["GOMAXPROCS"] != "2" || slices.Contains(bl.args, "--git-workers") {
		t.Errorf("pooled betterleaks: GOMAXPROCS=%q args %v", bl.env["GOMAXPROCS"], bl.args)
	}
	// One huge repository alone: GOMAXPROCS=4 and --git-workers 4 (the sweep sets Threads).
	o.Threads = 4
	bl = gitArgs("betterleaks", o)
	if bl.env["GOMAXPROCS"] != "4" || !hasArgs(bl.args, "--git-workers", "4") {
		t.Errorf("betterleaks with Threads=4: GOMAXPROCS=%q args %v", bl.env["GOMAXPROCS"], bl.args)
	}
	if gl := gitArgs("gitleaks", o); gl.env["GOMAXPROCS"] != "4" {
		t.Errorf("gitleaks with Threads=4: GOMAXPROCS=%q", gl.env["GOMAXPROCS"])
	}

	// Titus's workers are native threads that GOMAXPROCS does not bound.
	o.Threads = 0
	if ti := gitArgs("titus", o); !hasArgs(ti.args, "--workers", "2") || !hasArgs(ti.args, "--readers", "2") {
		t.Errorf("pooled titus: %v", ti.args)
	}
	o.Threads = 4
	if ti := gitArgs("titus", o); !hasArgs(ti.args, "--workers", "4") || !hasArgs(ti.args, "--readers", "4") {
		t.Errorf("titus with Threads=4: %v", ti.args)
	}

	// Trufflehog's concurrency is also its verification request rate: never more than two
	// requests at a time while it verifies.
	for _, c := range []struct {
		threads int
		verify  bool
		want    int
	}{{0, false, 2}, {4, false, 4}, {0, true, 2}, {8, true, 2}} {
		o := testOpts()
		o.Threads, o.Verify = c.threads, c.verify
		th := gitArgs("trufflehog", o)
		if a, ok := argWithPrefix(th.args, "--concurrency="); !ok || a != "--concurrency="+strconv.Itoa(c.want) {
			t.Errorf("trufflehog threads=%d verify=%v: %q, want --concurrency=%d", c.threads, c.verify, a, c.want)
		}
		if th.env["GOMAXPROCS"] != strconv.Itoa(max(c.threads, 2)) {
			t.Errorf("trufflehog threads=%d: GOMAXPROCS=%q", c.threads, th.env["GOMAXPROCS"])
		}
	}
}

// ----- P0-05, P0-12: the pre-commit call -----

func TestPreCommitCallIsHermetic(t *testing.T) {
	root := os.Getenv("KEYGUARD_HOME")
	empty := emptyTree(t)
	for _, name := range []string{"betterleaks", "gitleaks"} {
		t.Run(name, func(t *testing.T) {
			f := getFixture(t)
			e, read := recordingEngine(t, name, f.kr, "[]", "", 0)
			wt := worktree(t)
			writeLines(t, wt, "b.env", "A=1")
			gitIn(wt, nil, "add", "-A")
			if err := e.ScanStaged(context.Background(), wt, testOpts(), func(core.Hit) {}); err != nil {
				t.Fatal(err)
			}
			cs := read()
			if len(cs) != 1 {
				t.Fatalf("%d starts", len(cs))
			}
			c := cs[0]
			rwt := resolved(t, wt)
			// cwd: somewhere that holds nothing of the repository's and under the data root.
			if strings.HasPrefix(c.cwd, rwt) || !strings.HasPrefix(c.cwd, realpath(root)) {
				t.Errorf("working directory %s (repo %s, data root %s)", c.cwd, rwt, root)
			}
			// git is pointed at the repository by absolute paths, which survive the chdir.
			if d := c.env["GIT_DIR"]; !filepath.IsAbs(d) || resolved(t, d) != filepath.Join(rwt, ".git") {
				t.Errorf("GIT_DIR %q", d)
			}
			if d := c.env["GIT_WORK_TREE"]; !filepath.IsAbs(d) || resolved(t, d) != rwt {
				t.Errorf("GIT_WORK_TREE %q", d)
			}
			if d := c.env["GIT_INDEX_FILE"]; !filepath.IsAbs(d) || resolved(t, d) != filepath.Join(rwt, ".git", "index") {
				t.Errorf("GIT_INDEX_FILE %q", d)
			}
			// No .gitattributes can tell git to print "Binary files differ" for a file.
			if c.env["GIT_ATTR_SOURCE"] != empty {
				t.Errorf("GIT_ATTR_SOURCE %q, want the empty tree %s", c.env["GIT_ATTR_SOURCE"], empty)
			}
			// -c always (no .betterleaks.toml in a directory can stand in for it), inline markers
			// ignored, and the repository is not an argument: it is found by the environment.
			if cfg, ok := argAfter(c.args, "-c"); !ok || !filepath.IsAbs(cfg) {
				t.Errorf("no absolute -c in %v", c.args)
			}
			if !slices.Contains(c.args, "--ignore-gitleaks-allow") || !hasArgs(c.args, "--pre-commit", "--staged") {
				t.Errorf("args %v", c.args)
			}
			for _, a := range c.args {
				if resolved2(a) == rwt {
					t.Errorf("the repository path is an argument: %v", c.args)
				}
			}
		})
	}
}

func argAfter(args []string, flag string) (string, bool) {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return "", false
	}
	return args[i+1], true
}

func resolved2(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// Every history, directory and API call of every engine carries the allow-marker switch and a
// config of ours, and sees no attributes.
func TestHistoryCallsAreHermeticToo(t *testing.T) {
	empty := emptyTree(t)
	for _, name := range []string{"betterleaks", "gitleaks"} {
		t.Run(name, func(t *testing.T) {
			calls, _ := scanEverything(t, name, testOpts())
			if len(calls) < 3 {
				t.Fatalf("%d starts", len(calls))
			}
			for _, c := range calls {
				if !slices.Contains(c.args, "--ignore-gitleaks-allow") {
					t.Errorf("honors allow markers: %v", c.args)
				}
				if cfg, ok := argAfter(c.args, "-c"); !ok || !filepath.IsAbs(cfg) {
					t.Errorf("no absolute -c in %v", c.args)
				}
				// Whatever reads `git diff` or `git log -p` must see no attributes; a directory scan reads none.
				if c.args[0] == "git" && c.env["GIT_ATTR_SOURCE"] != empty {
					t.Errorf("GIT_ATTR_SOURCE %q in %v", c.env["GIT_ATTR_SOURCE"], c.args)
				}
				for _, k := range []string{"BETTERLEAKS_CONFIG", "GITLEAKS_CONFIG"} {
					if v, ok := c.env[k]; ok {
						t.Errorf("%s=%q reaches the engine", k, v)
					}
				}
			}
		})
	}
}

// emptyReport is what an engine prints when it finds nothing: trufflehog prints no lines at
// all, the others an empty JSON array.
func emptyReport(name string) string {
	if name == "trufflehog" {
		return ""
	}
	return "[]"
}

// realpath resolves symlinks in the longest prefix of p that exists (the data root is only
// created by the first scan, and /var is a link to /private/var on macOS).
func realpath(p string) string {
	rest := ""
	for q := p; ; q = filepath.Dir(q) {
		if r, err := filepath.EvalSymlinks(q); err == nil {
			return filepath.Join(r, rest)
		}
		if q == filepath.Dir(q) {
			return p
		}
		rest = filepath.Join(filepath.Base(q), rest)
	}
}
