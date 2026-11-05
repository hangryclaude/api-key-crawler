package selftest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"keyguard/internal/testkit"
)

// binPath is the real keyguard binary, built once. The selftest drives it the way git does.
var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "keyguard-selftest-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binPath = filepath.Join(dir, "keyguard")
	build := exec.Command("go", "build", "-o", binPath, "keyguard/cmd/keyguard")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building the binary under test: %v\n%s", err, out)
		os.Exit(1)
	}
	// A test once wrote through a symlink and replaced the real trufflehog. Whatever this
	// suite does on this Mac, testkit fails the run if an engine binary is not what it was.
	code := testkit.Run(m)
	os.RemoveAll(dir) // made above, holds the one binary
	os.Exit(code)
}

func table(rep *Report) string {
	var b bytes.Buffer
	rep.Table(&b)
	return b.String()
}

func byID(rep *Report) map[string]Check {
	m := map[string]Check{}
	for _, c := range rep.Checks {
		m[c.ID] = c
	}
	return m
}

// ----- the real thing -----

func TestRunPasses(t *testing.T) {
	rep, s, err := run(context.Background(), Options{Binary: binPath, TempDir: t.TempDir(), NoLatency: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + table(rep))
	got := byID(rep)
	all, _ := Catalog()
	for _, info := range all {
		c, ok := got[info.ID]
		switch {
		case info.Group == "speed":
			if ok {
				t.Errorf("%s ran although NoLatency was set", info.ID)
			}
		case !ok:
			t.Errorf("%s did not run", info.ID)
		case !c.OK:
			t.Errorf("%s failed: %s", info.ID, c.Detail)
		}
	}
	if !rep.OK || len(rep.Failed()) != 0 {
		t.Errorf("the report is not OK: %v", rep.Failed())
	}
	if len(rep.Latency) != 0 {
		t.Errorf("latency figures without latency checks: %+v", rep.Latency)
	}

	// Nothing the report says holds a fake, in the table or in the JSON a record is made from.
	js, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if n := s.leaks(table(rep) + string(js)); n != 0 {
		t.Errorf("the report holds %d planted secrets", n)
	}
	if len(s.fakes) < 10 {
		t.Errorf("only %d fakes were made; the audits had little to look for", len(s.fakes))
	}
	// And the machine is gone.
	if left, _ := filepath.Glob(filepath.Join(s.o.TempDir, "keyguard-gates-*")); len(left) != 0 {
		t.Errorf("the throwaway machine was left behind: %v", left)
	}
}

func TestSpeedWithinBudget(t *testing.T) {
	rep, _, err := run(context.Background(), Options{Binary: binPath, TempDir: t.TempDir(), Only: []string{"speed"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + table(rep))
	if len(rep.Latency) != 3 {
		t.Fatalf("want three latency figures, got %+v", rep.Latency)
	}
	for _, l := range rep.Latency {
		if l.Runs != DefaultRuns || l.Warmups != warmups || l.P50ms <= 0 || l.P95ms < l.P50ms || l.MaxMs < l.P95ms || l.Cores != runtime.NumCPU() {
			t.Errorf("implausible figures: %+v", l)
		}
		// The load average lags: a Mac that got busy half way through a measurement shows it only
		// at the end, so both readings count. Other work on this Mac is not the hook's fault.
		if load := max(l.Load1, loadAverage()); !l.OK && load > 2*float64(l.Cores) {
			t.Logf("%s is over budget at load %.0f on %d cores: not counted: %+v", l.Hook, load, l.Cores, l)
			continue
		}
		if !l.OK {
			t.Errorf("%s p50 %.1f ms is over its %.0f ms budget (load %.0f on %d cores)", l.Hook, l.P50ms, l.BudgetMs, l.Load1, l.Cores)
		}
	}
}

func TestOnlyRunsJustWhatWasAskedFor(t *testing.T) {
	rep, _, err := run(context.Background(), Options{Binary: binPath, TempDir: t.TempDir(), Only: []string{"reftx-noverify", "mirror"}})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range rep.Checks {
		ids = append(ids, c.ID)
		if !c.OK {
			t.Errorf("%s failed: %s", c.ID, c.Detail)
		}
	}
	if want := "machine,reftx-noverify,mirror-skip"; strings.Join(ids, ",") != want {
		t.Errorf("ran %v, want the machine and the two asked for (%s)", ids, want)
	}
	if _, _, err := run(context.Background(), Options{Binary: binPath, TempDir: t.TempDir(), Only: []string{"reftx-noverfy"}}); err == nil || !strings.Contains(err.Error(), `did you mean "reftx-noverify"`) {
		t.Errorf("a misspelt check must be an error that names the right one, not an empty pass: %v", err)
	}
	if _, _, err := run(context.Background(), Options{Binary: binPath, TempDir: t.TempDir(), Only: []string{"zzzzzzzz"}}); err == nil || strings.Contains(err.Error(), "did you mean") {
		t.Errorf("a name nothing is near should be refused without a wild guess: %v", err)
	}
}

// The checks the P0 work added, run alone on the real binary. They are the other half of
// TestBrokenGatesAreCaught: a check that every broken wrapper fails has to pass on the binary it
// was written for, and this is the quick way to see that a change to the hook wiring lost none.
func TestTheChecksOfTheP0WorkPassOnTheRealBinary(t *testing.T) {
	only := []string{"precommit-blind", "text-message", "text-tag", "text-refname", "text-push", "failopen-pins", "engines-clean"}
	rep, _, err := run(context.Background(), Options{Binary: binPath, TempDir: t.TempDir(), Only: only, NoLatency: true})
	if err != nil {
		t.Fatal(err)
	}
	got := byID(rep)
	for _, id := range only {
		switch c, ok := got[id]; {
		case !ok:
			t.Errorf("%s did not run", id)
		case !c.OK:
			t.Errorf("%s failed: %s", id, c.Detail)
		}
	}
}

// The selftest builds its own Mac. A caller whose HOME, global git config, data root and
// environment are full of traps must find them all untouched, and the traps never sprung.
func TestDoesNotTouchTheCallersMachine(t *testing.T) {
	trap := t.TempDir()
	home := filepath.Join(trap, "home")
	marker := filepath.Join(trap, "sprung")
	for _, d := range []string{home, filepath.Join(home, ".keyguard", "state", "known")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(trap, "gitconfig"): "[user]\n\tname = Trap\n\temail = trap@example.invalid\n" +
			"[hook \"trap-commit\"]\n\tevent = pre-commit\n\tcommand = touch " + shq(marker) + "\n" +
			"[hook \"trap-ref\"]\n\tevent = reference-transaction\n\tcommand = touch " + shq(marker) + "\n",
		filepath.Join(home, ".gitconfig"):                                "[user]\n\tname = Trap\n",
		filepath.Join(home, ".keyguard", "state", "known", "known.json"): "{not json",
	}
	for p, body := range files {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(trap, "gitconfig"))
	t.Setenv("KEYGUARD_HOME", filepath.Join(home, ".keyguard"))
	// What a hook sees when the selftest is started from inside one.
	t.Setenv("GIT_DIR", filepath.Join(trap, "nowhere.git"))
	t.Setenv("GIT_INDEX_FILE", filepath.Join(trap, "nowhere.index"))
	t.Setenv("GIT_WORK_TREE", trap)
	before := tree(t, trap)

	rep, _, err := run(context.Background(), Options{Binary: binPath, TempDir: t.TempDir(), Only: []string{"precommit-clean", "reftx-noverify", "push-known"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Checks {
		if !c.OK {
			t.Errorf("%s failed: %s", c.ID, c.Detail)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the caller's git config was read: its trap hook ran")
	}
	if after := tree(t, trap); after != before {
		t.Errorf("something under the caller's HOME changed:\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// tree lists every file under dir with its size and time, so a change shows as a difference.
func tree(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s %d %d", strings.TrimPrefix(p, dir), fi.Size(), fi.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}

func TestKeepLeavesTheMachineAndTempDirIsHonoured(t *testing.T) {
	tmp := t.TempDir()
	rep, s, err := run(context.Background(), Options{Binary: binPath, TempDir: tmp, Keep: true, Only: []string{"precommit-clean"}})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("%v", rep.Failed())
	}
	if filepath.Dir(s.dir) != tmp {
		t.Errorf("the machine is at %s, not under %s", s.dir, tmp)
	}
	if rep.Machine != s.dir || !strings.Contains(table(rep), "kept at "+s.dir) {
		t.Errorf("a kept machine must say where it is: %q", rep.Machine)
	}
	for _, p := range []string{s.gitconfig, filepath.Join(s.root, "state", "known", "known.json"), filepath.Join(s.root, "rules", "keyguard.toml")} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("Keep left no %s: %v", p, err)
		}
	}
}

func TestBinaryProblems(t *testing.T) {
	if _, err := Run(context.Background(), Options{}); err == nil {
		t.Error("no binary, no test")
	}
	if _, err := Run(context.Background(), Options{Binary: filepath.Join(t.TempDir(), "absent")}); err == nil {
		t.Error("a binary that is not there is an error, not a failed row")
	}
	notExec := filepath.Join(t.TempDir(), "keyguard")
	if err := os.WriteFile(notExec, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), Options{Binary: notExec}); err == nil {
		t.Error("a file that cannot run is an error")
	}

	// A binary that starts and fails at everything is a result: one failing row that says so,
	// quickly, and not a pile of cascading errors or a hang.
	exe := wrap(t, "exit 3")
	started := time.Now()
	rep, err := Run(context.Background(), Options{Binary: exe, TempDir: t.TempDir()})
	if err != nil {
		t.Fatalf("a broken binary is a failed layer, not an error: %v", err)
	}
	if rep.OK || len(rep.Checks) != 1 || rep.Checks[0].ID != "machine" || rep.Checks[0].OK || rep.Checks[0].Detail == "" {
		t.Errorf("a binary that exits 3 for everything: %+v", rep.Checks)
	}
	if d := time.Since(started); d > 20*time.Second {
		t.Errorf("a broken binary took %v to report", d)
	}
}

func TestCutShortIsNotAPass(t *testing.T) {
	// A full run takes 25 seconds or more; this one is stopped after eight, which is long enough
	// to be well into the checks on a quiet Mac and short enough to cut them off on a busy one.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	rep, err := Run(ctx, Options{Binary: binPath, TempDir: t.TempDir()})
	if err != nil {
		// So busy that even the machine could not be built in time: still not a pass.
		if !strings.Contains(err.Error(), "deadline") && !strings.Contains(err.Error(), "canceled") && !strings.Contains(err.Error(), "killed") {
			t.Fatalf("a run cut short should say why: %v", err)
		}
		return
	}
	last := rep.Checks[len(rep.Checks)-1]
	if rep.OK || last.ID != "interrupted" || !strings.Contains(last.Detail, "deadline") {
		t.Errorf("a run that was stopped must not read as passed: ok=%v last=%+v", rep.OK, last)
	}
}

// ----- the selftest has to be able to fail -----

// wrap makes a binary that is the real one except for what body does first. It is how a gate
// is broken on purpose: a selftest that no broken gate can fail proves nothing.
func wrap(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "keyguard")
	script := "#!/bin/sh\nreal=" + shq(binPath) + "\n" + body + "\nexec \"$real\" \"$@\"\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func hookIs(name string) string { return `[ "$1" = hook ] && [ "$2" = ` + name + ` ]` }

func TestBrokenGatesAreCaught(t *testing.T) {
	cases := []struct {
		name string
		body string
		only []string
		fail map[string]string // check id -> a word its detail must carry
		pass []string
	}{
		{
			name: "pre-commit does nothing",
			body: "if " + hookIs("pre-commit") + "; then exit 0; fi",
			only: []string{"precommit", "reftx-noverify"},
			fail: map[string]string{
				"precommit-known": "", "precommit-scanner": "", "precommit-message": "", "precommit-names": "",
				"precommit-forms": "", "precommit-allow": "", "precommit-blind": "", "precommit-husky": "", "precommit-worktree": "",
			},
			pass: []string{"precommit-clean", "reftx-noverify"},
		},
		{
			name: "reference-transaction does nothing",
			body: "if " + hookIs("reference-transaction") + "; then cat >/dev/null; exit 0; fi",
			only: []string{"reftx", "precommit-known", "precommit-worktree", "quiet-clone", "roots-add", "mirror", "text-message", "text-tag", "text-refname"},
			fail: map[string]string{"reftx-noverify": "", "reftx-ways": "", "precommit-worktree": "", "roots-add": "", "quiet-clone": "control", "mirror-skip": "control",
				"text-message": "was not blocked", "text-tag": "was not blocked", "text-refname": "was not blocked"},
			pass: []string{"precommit-known"},
		},
		{
			name: "pre-push does nothing",
			body: "if " + hookIs("pre-push") + "; then cat >/dev/null; exit 0; fi",
			only: []string{"prepush", "reftx-noverify", "text-push"},
			fail: map[string]string{"push-unknown": "", "push-rewrites": "", "push-known": "", "text-push": "was not blocked"},
			pass: []string{"push-clean", "reftx-noverify"},
		},
		{
			name: "reference-transaction refuses everything",
			body: `if ` + hookIs("reference-transaction") + ` && [ "$3" = prepared ]; then cat >/dev/null; echo "keyguard: ref update blocked: no" >&2; exit 1; fi`,
			only: []string{"precommit-clean", "quiet-clone", "push-clean", "mirror"},
			fail: map[string]string{"precommit-clean": "", "quiet-clone": "", "push-clean": "", "mirror-skip": ""},
		},
		{
			name: "pre-commit refuses everything",
			body: `if ` + hookIs("pre-commit") + `; then echo "keyguard: commit blocked: no" >&2; exit 1; fi`,
			only: []string{"precommit-clean", "precommit-names"},
			fail: map[string]string{"precommit-clean": "", "precommit-names": ""},
		},
		{
			name: "pre-push refuses everything",
			body: `if ` + hookIs("pre-push") + `; then cat >/dev/null; echo "keyguard: push blocked: no" >&2; exit 1; fi`,
			only: []string{"push-clean", "quiet-branch"},
			fail: map[string]string{"push-clean": "", "quiet-branch": ""},
		},
		{
			name: "a hook that prints the secret it blocked",
			body: `if ` + hookIs("pre-commit") + `; then "$real" "$@"; code=$?; if [ $code -ne 0 ]; then git diff --cached >&2; fi; exit $code; fi`,
			only: []string{"precommit-known", "precommit-scanner", "reftx-noverify", "no-leaks"},
			fail: map[string]string{"precommit-known": "planted secret", "precommit-scanner": "planted secret", "no-leaks": "planted secret"},
			pass: []string{"reftx-noverify"},
		},
		{
			name: "a hook that gives up quietly",
			body: `if ` + hookIs("pre-commit") + `; then echo "keyguard: warning: pre-commit hook hit an internal error (x); allowing" >&2; fi`,
			only: []string{"precommit-known", "hooks-quiet"},
			fail: map[string]string{"hooks-quiet": "fail-open"},
			pass: []string{"precommit-known"},
		},
		{
			name: "a ref gate that believes the environment",
			body: `if ` + hookIs("reference-transaction") + ` && [ "$GIT_REFLOG_ACTION" = fetch ]; then cat >/dev/null; exit 0; fi`,
			only: []string{"reftx"},
			fail: map[string]string{"reftx-ways": "GIT_REFLOG_ACTION"},
			pass: []string{"reftx-noverify"},
		},
		{
			name: "commit-msg does nothing",
			body: "if " + hookIs("commit-msg") + "; then exit 0; fi",
			only: []string{"text-message", "reftx-noverify"},
			fail: map[string]string{"text-message": "commit message blocked"},
			pass: []string{"reftx-noverify"},
		},
		{
			// STEAL P0-05, P0-12: the repo being committed to is the attacker's to write.
			name: "a pre-commit that honours an allow comment, an ignore file or a gitattributes file",
			body: "if " + hookIs("pre-commit") + "; then\n" +
				"  if git diff --cached 2>/dev/null | grep -qE 'gitleaks:allow|betterleaks:allow'; then exit 0; fi\n" +
				"  if [ -e .gitleaksignore ] || [ -e .betterleaksignore ] || [ -e .gitattributes ]; then exit 0; fi\n" +
				"fi",
			only: []string{"precommit-blind", "precommit-allow", "precommit-clean"},
			fail: map[string]string{"precommit-blind": "", "precommit-allow": ""},
			pass: []string{"precommit-clean"},
		},
		{
			// STEAL P0-01: the refusal of a changed engine has to be said, or nobody knows the scan lost it.
			name: "a hook that skips a changed engine in silence",
			body: "if " + hookIs("pre-commit") + "; then\n" +
				"  err=\"$HOME/.wrapper-err\"\n" +
				"  \"$real\" \"$@\" 2>\"$err\"; code=$?\n" +
				"  grep -v 'is not the binary that was pinned' \"$err\" >&2\n" +
				"  exit $code\n" +
				"fi",
			only: []string{"failopen-pins"},
			fail: map[string]string{"failopen-pins": "nobody was told"},
		},
		{
			// STEAL P0-06: titus keeps its findings, in the clear, in a datastore unless it is told not to.
			name: "a hook that leaves a titus datastore behind",
			body: "if " + hookIs("pre-commit") + "; then : > \"$HOME/datastore.db\"; fi",
			only: []string{"precommit-clean", "engines-clean"},
			fail: map[string]string{"engines-clean": "datastore"},
			pass: []string{"precommit-clean"},
		},
		{
			name: "an engine that leaves its scratch directory behind",
			body: "if " + hookIs("pre-commit") + "; then mkdir -p \"$KEYGUARD_HOME/tmp/engine-left\"; fi",
			only: []string{"precommit-clean", "engines-clean"},
			fail: map[string]string{"engines-clean": "scratch"},
			pass: []string{"precommit-clean"},
		},
		{
			name: "a hook that dies on a broken config instead of using the defaults",
			body: `if ` + hookIs("pre-commit") + ` && grep -q 'not json' "$HOME/.keyguard/state/config.json" 2>/dev/null; then echo "keyguard: fatal: config" >&2; exit 1; fi`,
			only: []string{"failopen-config", "precommit-clean"},
			fail: map[string]string{"failopen-config": ""},
			pass: []string{"precommit-clean"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			exe := wrap(t, tc.body)
			rep, s, err := run(context.Background(), Options{Binary: exe, TempDir: t.TempDir(), Only: tc.only, NoLatency: true})
			if err != nil {
				t.Fatal(err)
			}
			got := byID(rep)
			for id, word := range tc.fail {
				c, ok := got[id]
				switch {
				case !ok:
					t.Errorf("%s did not run", id)
				case c.OK:
					t.Errorf("%s passed although the gate was broken", id)
				case !strings.Contains(c.Detail, word):
					t.Errorf("%s failed, but its detail lacks %q: %s", id, word, c.Detail)
				}
			}
			for _, id := range tc.pass {
				if c, ok := got[id]; !ok || !c.OK {
					t.Errorf("%s should not be affected by this break: %+v", id, c)
				}
			}
			if rep.OK {
				t.Error("the report says everything is fine")
			}
			// Even a broken run must not print a secret.
			js, _ := json.Marshal(rep)
			if n := s.leaks(table(rep) + string(js)); n != 0 {
				t.Errorf("the report holds %d planted secrets", n)
			}
		})
	}
}

// A slow hook is caught, and a hook that was only slow while something else used the machine
// is measured again and judged by its better set, with the report saying it did.
func TestSpeedIsJudgedAgainstTheBudget(t *testing.T) {
	t.Run("slow", func(t *testing.T) {
		t.Parallel()
		exe := wrap(t, "if "+hookIs("pre-commit")+"; then sleep 0.25; fi")
		rep, _, err := run(context.Background(), Options{Binary: exe, TempDir: t.TempDir(), Only: []string{"speed-precommit"}, Runs: 3})
		if err != nil {
			t.Fatal(err)
		}
		c := byID(rep)["speed-precommit"]
		if c.OK || !strings.Contains(c.Detail, "over budget") || len(rep.Latency) != 1 {
			t.Fatalf("a hook that sleeps a quarter of a second must fail its budget: %+v %+v", c, rep.Latency)
		}
		if l := rep.Latency[0]; l.OK || !l.Retried || l.P50ms < 250 {
			t.Errorf("figures: %+v", l)
		}
	})
	t.Run("slow once", func(t *testing.T) {
		t.Parallel()
		counter := filepath.Join(t.TempDir(), "count")
		// Slow for the first six runs: the base commit, two warm-ups and three timed runs.
		exe := wrap(t, "if "+hookIs("pre-commit")+"; then n=$(cat "+shq(counter)+" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "+shq(counter)+"; if [ $n -le 6 ]; then sleep 0.25; fi; fi")
		rep, _, err := run(context.Background(), Options{Binary: exe, TempDir: t.TempDir(), Only: []string{"speed-precommit"}, Runs: 3})
		if err != nil {
			t.Fatal(err)
		}
		c := byID(rep)["speed-precommit"]
		if !c.OK || !strings.Contains(c.Detail, "measured twice") || len(rep.Latency) != 1 || !rep.Latency[0].Retried {
			t.Errorf("a hook that was slow once should pass on its second set, and say it was measured twice: %+v %+v", c, rep.Latency)
		}
	})
}
