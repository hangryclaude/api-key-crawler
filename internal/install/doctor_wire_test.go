package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/engines"
)

// One check for each piece the hardening added, each with the command that fixes it.

func TestDoctorCommitMsgGate(t *testing.T) {
	w := healthyWorld(t)
	r := w.doctor()
	wantCheck(t, r, "hooks.commitmsg", OK, "commit-msg gate is installed")
	gitOut(t, w.dir, "config", "--file", w.gitconfig, "--remove-section", "hook.keyguard-commitmsg")
	c := wantCheck(t, w.doctor(), "hooks.commitmsg", Fail, "not in")
	if c.Fix != "keyguard install" || !slices.Contains(c.Layers, LayerCommit) {
		t.Errorf("fix %q layers %v: a missing commit-msg gate is the commit gate being down", c.Fix, c.Layers)
	}
	gitOut(t, w.dir, "config", "--file", w.gitconfig, "hook.keyguard-commitmsg.enabled", "false")
	wantCheck(t, w.doctor(), "hooks.commitmsg", Fail, "not in")
}

// Claude Code calls a PreToolUse hook only for the tools its matcher names (P0-14). v1 wrote a
// Bash-only matcher; the doctor says what that leaves open, and the registration line mends it.
func TestDoctorGuardMatcher(t *testing.T) {
	w := healthyWorld(t)
	wantCheck(t, w.doctor(), "guard.matcher", OK, "Bash, Write, Edit, MultiEdit, NotebookEdit and MCP")

	settings := filepath.Join(w.home, ".claude", "settings.json")
	old := `{"theme":"light","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + guardCommand(w.paths.Bin) + `"}]}]}}`
	mustf(t, os.WriteFile(settings, []byte(old), 0o600), "write")
	r := w.doctor()
	wantCheck(t, r, "guard.claude", OK, "registered")
	c := wantCheck(t, r, "guard.matcher", Warn, "not called for Write, Edit, MultiEdit, NotebookEdit, mcp__*")
	if !strings.HasPrefix(c.Fix, "! ") {
		t.Errorf("the fix should be the registration line: %q", c.Fix)
	}
	if triage := r.Triage(); !slices.Contains(triage.NeedsUser, c.Fix) {
		t.Errorf("widening the matcher edits their settings, so it is for them to run: %v", triage.NeedsUser)
	}

	// Running the line widens that entry and adds no second one.
	runBang(t, w.home, c.Fix)
	r = w.doctor()
	wantCheck(t, r, "guard.matcher", OK, "called for")
	b, _ := os.ReadFile(settings)
	if strings.Count(string(b), "guard claude") != 1 || !strings.Contains(string(b), `"theme": "light"`) {
		t.Errorf("the line did not mend the entry in place and keep the rest: %s", b)
	}

	// A matcher of "*" or "" names everything; one that is a regular expression is read as one.
	for matcher, covered := range map[string]bool{"*": true, "": true, "Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*": true,
		"Bash|Write": false, "(Bash|Write|Edit|MultiEdit|NotebookEdit)": false, "Edit|Write|Bash|MultiEdit|NotebookEdit|mcp__github__.*": false, "(": false} {
		reg := `{"hooks":{"PreToolUse":[{"matcher":"` + matcher + `","hooks":[{"type":"command","command":"` + guardCommand(w.paths.Bin) + `"}]}]}}`
		mustf(t, os.WriteFile(settings, []byte(reg), 0o600), "write")
		uncovered, registered, err := ClaudeUncovered(settings, w.paths.Bin)
		if err != nil || !registered || (len(uncovered) == 0) != covered {
			t.Errorf("matcher %q: uncovered %v registered %v err %v, want covered=%v", matcher, uncovered, registered, err, covered)
		}
	}
}

func TestClaudeRegistrationMendsAnOldEntryAndLeavesOthersAlone(t *testing.T) {
	home := t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	mustf(t, os.MkdirAll(filepath.Dir(settings), 0o755), "mkdir")
	bin := "/Users/me/.keyguard/bin/keyguard"
	// An entry that shares its group with another hook cannot be widened without widening
	// that hook, so ours is taken out of the group and registered on its own.
	orig := `{"hooks":{"PreToolUse":[` +
		`{"matcher":"Bash","hooks":[{"type":"command","command":"python3 /x/guard.py"},{"type":"command","command":"` + guardCommand(bin) + `"}]},` +
		`{"matcher":"Read","hooks":[{"type":"command","command":"echo reading"}]}]}}`
	mustf(t, os.WriteFile(settings, []byte(orig), 0o600), "write")
	line := ClaudeRegistration(bin)
	runBang(t, home, line)
	once, _ := os.ReadFile(settings)
	runBang(t, home, line)
	twice, _ := os.ReadFile(settings)
	if string(once) != string(twice) {
		t.Errorf("the second run changed the file:\n%s\n%s", once, twice)
	}
	if strings.Count(string(once), "guard claude") != 1 || !strings.Contains(string(once), "python3 /x/guard.py") || !strings.Contains(string(once), "echo reading") {
		t.Errorf("another hook was lost or ours is there twice: %s", once)
	}
	if un, reg, err := ClaudeUncovered(settings, bin); err != nil || !reg || len(un) != 0 {
		t.Errorf("after the line: uncovered %v registered %v %v", un, reg, err)
	}
	// The hook that shared the group is still on Bash only.
	if !strings.Contains(string(once), `"matcher": "Bash"`) {
		t.Errorf("the other hook's matcher changed: %s", once)
	}
}

func TestDoctorLaunchdKnowsTheWeeklyEngineCheck(t *testing.T) {
	w := healthyWorld(t)
	wantCheck(t, w.doctor(), "launchd.upgrade", OK, "is loaded")
	delete(w.run.loaded, LabelUpgrade)
	c := wantCheck(t, w.doctor(), "launchd.upgrade", Fail, "not loaded")
	if !slices.Contains(c.Layers, LayerUpgrade) || c.Fix != "keyguard install" {
		t.Errorf("%+v", c)
	}
	// A poll plist from before the minute cadence differs from what install writes now.
	w.run.loaded[LabelUpgrade] = true
	old := filepath.Join(w.launch, LabelPoll+".plist")
	b, _ := os.ReadFile(old)
	mustf(t, os.WriteFile(old, []byte(strings.Replace(string(b), "<integer>60</integer>", "<integer>600</integer>", 1)), 0o644), "write")
	wantCheck(t, w.doctor(), "launchd.poll", Warn, "differs")
}

func TestDoctorEngineScratchDirectory(t *testing.T) {
	w := healthyWorld(t)
	wantCheck(t, w.doctor(), "engines.tmp", OK, "private and empty")

	left := filepath.Join(w.paths.Tmp, "betterleaks-123456")
	mustf(t, os.MkdirAll(left, 0o700), "mkdir")
	c := wantCheck(t, w.doctor(), "engines.tmp", Warn, "left behind: a run died")
	if !strings.Contains(c.Fix, "mv ") || strings.Contains(c.Fix, "rm ") {
		t.Errorf("a leftover scratch directory may hold diff text: move it, never remove it: %s", c.Fix)
	}
	// While a sweep holds the run lock, its scratch directories are in use.
	mustf(t, os.WriteFile(w.paths.Lock, []byte("pid="+itoa(os.Getpid())+"\ntoken=x\nstarted=2026-11-03T09:00:00Z\n"), 0o600), "lock")
	wantCheck(t, w.doctor(), "engines.tmp", OK, "private and empty")
	os.Remove(w.paths.Lock)
	mustf(t, os.Remove(left), "clear")

	mustf(t, os.Chmod(w.paths.Tmp, 0o755), "chmod")
	c = wantCheck(t, w.doctor(), "engines.tmp", Warn, "0755, want 0700")
	if c.Fix != "chmod 700 "+shellQuote(w.paths.Tmp) {
		t.Errorf("fix: %s", c.Fix)
	}
	mustf(t, os.Chmod(w.paths.Tmp, 0o700), "chmod back")

	mustf(t, os.Remove(w.paths.Tmp), "remove tmp")
	wantCheck(t, w.doctor(), "engines.tmp", Warn, "does not exist yet")
}

// titus keeps every match in a SQLite file, in the clear, unless it is run with --output :memory:
// (P0-06), and its Hyperscan cache is built once so a hook does not pay for it.
func TestDoctorTitusCacheAndDatastore(t *testing.T) {
	w := healthyWorld(t)
	if _, ok := w.doctor().check("engine.titus.cache"); ok {
		t.Fatal("titus is in no tier, so there is nothing to check about its cache")
	}
	cfg, _ := LoadConfig(w.paths, w.home)
	cfg.Tiers[TierPoll] = append(cfg.Tiers[TierPoll], "titus")
	mustf(t, cfg.Save(w.paths), "save")

	wantCheck(t, w.doctor(), "engine.titus.cache", Warn, "no rule cache yet")
	mustf(t, os.MkdirAll(w.paths.TitusCache, 0o700), "mkdir")
	mustf(t, os.WriteFile(filepath.Join(w.paths.TitusCache, "rules.bin"), []byte("x"), 0o600), "cache")
	wantCheck(t, w.doctor(), "engine.titus.cache", OK, "rule cache and no datastore")

	for _, where := range []string{
		filepath.Join(w.paths.State, "datastore.db"),
		filepath.Join(w.paths.Tmp, "titus-1", "scan.ds"),
	} {
		mustf(t, os.MkdirAll(filepath.Dir(where), 0o700), "mkdir")
		mustf(t, os.WriteFile(where, []byte("sqlite"), 0o600), "write")
		c := wantCheck(t, w.doctor(), "engine.titus.cache", Fail, "left a datastore behind")
		if !strings.Contains(c.Fix, "mv ") || strings.Contains(c.Fix, "rm ") || !strings.Contains(c.Fix, filepath.Base(where)) {
			t.Errorf("fix for %s: %s", filepath.Base(where), c.Fix)
		}
		if strings.Contains(c.Summary+c.Detail, "sqlite") {
			t.Error("the report quoted the datastore")
		}
		mustf(t, os.Remove(where), "clear")
		os.Remove(filepath.Dir(where))
	}
}

func TestDoctorUpgradeRecord(t *testing.T) {
	w := healthyWorld(t)
	if _, ok := w.doctor().check("engines.upgrade"); ok {
		t.Fatal("the weekly check has not run, so the doctor has nothing to say about it")
	}
	rec := func(at time.Duration, e ...UpgradeEngine) {
		t.Helper()
		mustf(t, SaveUpgrade(w.paths, UpgradeRecord{At: w.clock.Add(-at).Format(time.RFC3339), Engines: e}, ""), "save")
	}

	rec(24*time.Hour, UpgradeEngine{Engine: "betterleaks", Pinned: "9.9.9", Latest: "9.9.9"})
	wantCheck(t, w.doctor(), "engines.upgrade", OK, "pinned engines are the best on offer")

	rec(24*time.Hour, UpgradeEngine{Engine: "titus", Pinned: "1.2.10", Latest: "1.3.0", Switch: true})
	r := w.doctor()
	c := wantCheck(t, r, "engines.upgrade", Warn, "passes the bench gate: titus 1.3.0")
	if c.Fix != "keyguard engines check-upgrade --apply" {
		t.Errorf("fix: %q", c.Fix)
	}
	if !slices.Contains(r.Triage().NeedsUser, c.Fix) || slices.Contains(r.Triage().Actions, c.Fix) {
		t.Errorf("changing which scanner binary every gate trusts is their call, not an agent's: %+v", r.Triage())
	}

	rec(24*time.Hour, UpgradeEngine{Engine: "titus", Pinned: "1.2.10", Latest: "1.3.0", Switch: true, Applied: true})
	wantCheck(t, w.doctor(), "engines.upgrade", OK, "ran")

	rec(24*time.Hour, UpgradeEngine{Engine: "trufflehog", Pinned: "3.99.8", Error: "rate limited"})
	wantCheck(t, w.doctor(), "engines.upgrade", Warn, "could not look at trufflehog")

	rec(20*24*time.Hour, UpgradeEngine{Engine: "betterleaks", Pinned: "9.9.9", Latest: "9.9.9"})
	wantCheck(t, w.doctor(), "engines.upgrade", Warn, "last ran 20 days ago")
}

// GitHub's own scanning is checked from the summary the survey left: the doctor writes nothing and
// asks nothing, and a feature that went from on to off is a failure (P0-19).
func TestDoctorGitHubProtection(t *testing.T) {
	w := healthyWorld(t)
	wantCheck(t, w.doctor(), "github.protection", OK, "GitHub protects 1 of 1 repos")

	mustf(t, SaveProtection(w.paths, Protection{At: w.clock.Add(-time.Hour).Format(time.RFC3339), Headline: "GitHub protects 11 of 13 repos",
		Repos: 13, Public: 13, Protected: 11, GapCount: 2, Gaps: []ProtectionGap{{Source: "github.com/o/a", Off: []string{"push_protection"}}, {Source: "github.com/o/b", Off: []string{"scanning"}}}}), "save")
	c := wantCheck(t, w.doctor(), "github.protection", Warn, "2 public repos lack secret scanning or push protection")
	if c.Fix != "keyguard github-settings --apply" {
		t.Errorf("fix: %q", c.Fix)
	}

	mustf(t, SaveProtection(w.paths, Protection{At: w.clock.Add(-time.Hour).Format(time.RFC3339), Headline: "GitHub protects 12 of 13 repos",
		Drift: []ProtectionDrift{{Source: "github.com/o/a", Feature: "secret_scanning", Was: "enabled", Now: "disabled"}}}), "save")
	c = wantCheck(t, w.doctor(), "github.protection", Fail, "went off on o/a secret scanning")
	for _, l := range w.doctor().Layers() {
		if l.Name == LayerGitHub && (l.OK || l.Fix != "keyguard github-settings --apply") {
			t.Errorf("layer %+v: a drift takes the layer down and names the fix", l)
		}
	}

	w.protectionRecord(5 * 24 * time.Hour)
	wantCheck(t, w.doctor(), "github.protection", Warn, "last surveyed 5 days ago")
	os.Remove(ProtectionPath(w.paths))
	c = wantCheck(t, w.doctor(), "github.protection", Warn, "has not been looked at")
	if c.Fix != "keyguard github-settings" {
		t.Errorf("fix: %q", c.Fix)
	}
}

// The clock check is the one place the full doctor asks GitHub anything, and it asks the one
// request that costs no quota. This Mac has run two hours fast.
func TestDoctorClock(t *testing.T) {
	w := healthyWorld(t)
	skew := func(d time.Duration, err error) func(*DoctorOptions) {
		return func(o *DoctorOptions) { o.Skew = func(context.Context) (time.Duration, error) { return d, err } }
	}
	if _, ok := w.doctor().check("clock"); ok {
		t.Error("with nothing to ask GitHub through, the clock is not checked")
	}
	wantCheck(t, w.doctor(skew(20*time.Second, nil)), "clock", OK, "within a minute of GitHub's")
	wantCheck(t, w.doctor(skew(-59*time.Second, nil)), "clock", OK, "within a minute")
	c := wantCheck(t, w.doctor(skew(119*time.Minute+34*time.Second, nil)), "clock", Fail, "1h59m34s ahead of GitHub's")
	if !strings.Contains(c.Fix, "Date & Time") || !strings.Contains(c.Detail, "launchd") {
		t.Errorf("the failure should say what it hurts and what to do: %+v", c)
	}
	wantCheck(t, w.doctor(skew(-3*time.Minute, nil)), "clock", Fail, "3m0s behind GitHub's")
	wantCheck(t, w.doctor(skew(0, errors.New("gh: no network"))), "clock", Warn, "could not ask GitHub")

	called := false
	w.doctor(func(o *DoctorOptions) {
		o.Quick = true
		o.Skew = func(context.Context) (time.Duration, error) { called = true; return 0, nil }
	})
	if called {
		t.Error("the quick doctor made a request")
	}
}

func TestDoctorRulesLoadInBetterleaks(t *testing.T) {
	w := healthyWorld(t)
	wantCheck(t, w.doctor(), "rules.betterleaks", OK, "463 defaults and 12 of keyguard's")

	answer := func(with, without string) func(*DoctorOptions) {
		return func(o *DoctorOptions) {
			inner := o.Run
			o.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if len(args) >= 2 && args[0] == "config" && args[1] == "check" {
					if len(args) > 2 {
						return []byte(with), nil
					}
					return []byte(without), nil
				}
				return inner(ctx, name, args...)
			}
		}
	}
	c := wantCheck(t, w.doctor(answer("OK: 470 rules", "OK: 463 rules")), "rules.betterleaks", Fail, "adds 7, not 12")
	if !slices.Contains(c.Layers, LayerCommit) {
		t.Errorf("a rules file that does not load makes every pre-commit scan an engine error: %v", c.Layers)
	}
	wantCheck(t, w.doctor(answer("config error: line 4", "OK: 463 rules")), "rules.betterleaks", Fail, "does not accept the rules file")
	if _, ok := w.doctor(func(o *DoctorOptions) { o.Quick = true }).check("rules.betterleaks"); ok {
		t.Error("the quick doctor started betterleaks")
	}
}

// A pinned binary that changed is a failure of the engine, found with the engines' own check.
func TestDoctorPinFailureNamesBothHashesAndOnlyThat(t *testing.T) {
	w := healthyWorld(t)
	cfg, _ := LoadConfig(w.paths, w.home)
	mustf(t, os.WriteFile(cfg.Engines["trufflehog"], []byte("#!/bin/sh\necho 'trufflehog version 9.9.9'\n# swapped\n"), 0o755), "swap")
	r := w.doctor()
	c := wantCheck(t, r, "engine.trufflehog", Fail, "is not the binary that was pinned")
	want := cfg.Pins["trufflehog"].SHA256[:12]
	if !strings.Contains(c.Summary, "pinned "+want) {
		t.Errorf("the pinned hash is not shown: %s", c.Summary)
	}
	for _, id := range []string{"engine.betterleaks", "engine.gitleaks"} {
		wantCheck(t, r, id, OK, "matches its pin")
	}
	if !slices.Contains(r.Triage().NeedsUser, c.Fix) {
		t.Errorf("pinning a binary says which scanner every gate trusts, which is their call: %+v", r.Triage())
	}
	// The report names no value and the failure is the same on every run.
	var pe *engines.PinError
	e, _ := engines.New("trufflehog", cfg.Engines["trufflehog"], nopFP{}, cfg.EngineOptions(w.paths)...)
	if !errors.As(engines.CheckPin(e), &pe) {
		t.Error("the engine itself agrees it would not run")
	}
}
