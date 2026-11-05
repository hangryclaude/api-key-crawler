package install

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory"
	"keyguard/internal/known"
	"keyguard/internal/mirror"
)

// healthyWorld is a machine where everything the doctor checks is in order: installed with
// real pins, guard registered, a secret learned, a poll five minutes ago, a mirror for the
// one source in the inventory, and a selftest an hour ago.
func healthyWorld(t *testing.T) *world {
	t.Helper()
	w := newWorld(t)
	w.install()

	settings := filepath.Join(w.home, ".claude", "settings.json")
	mustf(t, os.MkdirAll(filepath.Dir(settings), 0o755), "mkdir claude")
	reg := `{"hooks":{"PreToolUse":[{"matcher":"` + GuardMatcher + `","hooks":[{"type":"command","command":"` + guardCommand(w.paths.Bin) + `"}]}]}}`
	mustf(t, os.WriteFile(settings, []byte(reg), 0o600), "write settings")

	env := filepath.Join(w.home, "dev", "app", ".env")
	mustf(t, os.MkdirAll(filepath.Dir(env), 0o755), "mkdir dev")
	mustf(t, os.WriteFile(env, []byte("API_KEY=sk-proj-"+randStr(t, alnum, 40)+"\n"), 0o600), "write env")
	_, err := known.Learn(known.Options{Root: w.paths.Root, Home: w.home, GHUsers: []string{}})
	mustf(t, err, "learn")

	src := core.Source{ID: "github.com/o/n", Kind: "repo", Owner: "o", Name: "n", Visibility: core.Public, PushedAt: "2026-11-03T10:00:00Z"}
	mustf(t, inventory.SaveSnapshot(w.paths.Inventory, []core.Source{src}, w.clock), "snapshot")
	m, err := mirror.New(mirror.Config{Root: w.paths.Mirrors})
	mustf(t, err, "mirror")
	mustf(t, os.MkdirAll(m.Path(src), 0o700), "mkdir mirror")

	w.runRecord("poll", 5*time.Minute)
	w.selftestRecord(true, time.Hour)
	w.protectionRecord(time.Hour)
	w.run.loaded[LabelPoll], w.run.loaded[LabelDeep], w.run.loaded[LabelUpgrade] = true, true, true
	return w
}

func (w *world) runRecord(kind string, ago time.Duration) {
	w.t.Helper()
	fin := w.clock.Add(-ago)
	b, _ := json.Marshal(core.RunStats{Kind: kind, Started: fin.Add(-time.Minute).Format(time.RFC3339), Finished: fin.Format(time.RFC3339)})
	name := fin.Format("20060102T150405.000Z") + ".json"
	mustf(w.t, os.MkdirAll(w.paths.Runs, 0o700), "mkdir runs")
	mustf(w.t, os.WriteFile(filepath.Join(w.paths.Runs, name), b, 0o600), "write run")
}

// protectionRecord is the survey of GitHub's own protection the daily poll leaves: everything public is on.
func (w *world) protectionRecord(ago time.Duration) {
	w.t.Helper()
	mustf(w.t, SaveProtection(w.paths, Protection{
		At: w.clock.Add(-ago).Format(time.RFC3339), Headline: "GitHub protects 1 of 1 repos", Repos: 1, Public: 1, Protected: 1,
	}), "write protection")
}

func (w *world) selftestRecord(ok bool, ago time.Duration) {
	w.t.Helper()
	rec := SelftestRecord{At: w.clock.Add(-ago).Format(time.RFC3339), OK: ok, Layers: []SelftestLayer{{Name: "commit gate", OK: ok}, {Name: "ref gate", OK: true}}}
	b, _ := json.Marshal(rec)
	mustf(w.t, os.WriteFile(SelftestPath(w.paths), b, 0o600), "write selftest")
}

func (w *world) doctor(mod ...func(*DoctorOptions)) Report {
	w.t.Helper()
	o := DoctorOptions{Options: w.opts(), Probe: w.probe}
	o.Now = func() time.Time { return w.clock }
	o.Executable = ""
	for _, m := range mod {
		m(&o)
	}
	r, err := Doctor(context.Background(), o)
	if err != nil {
		w.t.Fatalf("Doctor: %v", err)
	}
	return r
}

func (r Report) check(id string) (Check, bool) {
	for _, c := range r.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return Check{}, false
}

func wantCheck(t *testing.T, r Report, id string, st Status, summaryHas string) Check {
	t.Helper()
	c, ok := r.check(id)
	if !ok {
		t.Fatalf("no check %q in %v", id, ids(r))
	}
	if c.Status != st || !strings.Contains(c.Summary, summaryHas) {
		t.Fatalf("%s: got %s %q, want %s containing %q\ndetail: %s", id, c.Status, c.Summary, st, summaryHas, c.Detail)
	}
	if st != OK && c.Fix == "" {
		t.Errorf("%s is %s but names no fix", id, st)
	}
	return c
}

func ids(r Report) []string {
	var out []string
	for _, c := range r.Checks {
		out = append(out, c.ID+"="+string(c.Status))
	}
	return out
}

func TestDoctorHealthyMachine(t *testing.T) {
	w := healthyWorld(t)
	before := tree(t, w.dir)
	r := w.doctor()
	if !r.Healthy || r.ExitCode() != 0 {
		for _, c := range r.Checks {
			if c.Status != OK {
				t.Errorf("%s %s: %s (%s) fix: %s", c.ID, c.Status, c.Summary, c.Detail, c.Fix)
			}
		}
		t.Fatalf("a healthy machine reported: %d ok, %d warn, %d fail", r.Ok, r.Warnings, r.Failures)
	}
	// Everything PLAN.md asks the doctor to look at is among the checks.
	for _, id := range []string{"git.version", "hooks.precommit", "hooks.prepush", "hooks.reftx", "hooks.binary", "guard.claude",
		"hooks.commitmsg", "guard.matcher", "launchd.poll", "launchd.deep", "launchd.upgrade", "sweep.age", "engine.betterleaks", "engine.gitleaks", "engine.trufflehog", "engine.titus",
		"engines.tmp", "rules.betterleaks", "github.protection",
		"rules", "known.perms", "known.store", "state.files", "mirrors", "selftest.last", "notify", "gh.auth", "config"} {
		if _, ok := r.check(id); !ok {
			t.Errorf("the doctor does not check %s", id)
		}
	}
	if d := diffTrees(before, tree(t, w.dir)); d != "" {
		t.Errorf("the doctor wrote to disk:\n%s", d)
	}
	if r.SchemaVersion != DoctorSchemaVersion || r.Quick {
		t.Errorf("report header: %+v", r)
	}
	b, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(b), `"schema_version":1`) {
		t.Errorf("json: %s %v", b, err)
	}
	// Every layer is up.
	got := map[string]bool{}
	for _, l := range r.Layers() {
		got[l.Name] = l.OK
	}
	for _, name := range []string{LayerCommit, LayerPush, LayerRef, LayerGuard, LayerPoll, LayerDeep, LayerEngines, LayerKnown, LayerSelftest} {
		if ok, present := got[name]; !present || !ok {
			t.Errorf("layer %q: present=%v ok=%v", name, present, ok)
		}
	}
}

func TestDoctorOnAMachineWithNothingInstalled(t *testing.T) {
	w := newWorld(t)
	r := w.doctor()
	if r.Healthy || r.ExitCode() != 1 {
		t.Fatal("nothing is installed, yet the doctor is happy")
	}
	for _, id := range []string{"hooks.precommit", "hooks.prepush", "hooks.reftx"} {
		wantCheck(t, r, id, Fail, "not in")
	}
	wantCheck(t, r, "hooks.binary", Fail, "silently off")
	wantCheck(t, r, "launchd.poll", Fail, "no plist")
	wantCheck(t, r, "sweep.age", Fail, "no poll has run yet")
	wantCheck(t, r, "guard.claude", Warn, "not registered")
	wantCheck(t, r, "known.store", Warn, "no secrets are learned")
	wantCheck(t, r, "selftest.last", Warn, "never run")
	// The fix for a missing guard is the line the user runs.
	if c, _ := r.check("guard.claude"); !strings.HasPrefix(c.Fix, "! ") {
		t.Errorf("guard fix: %q", c.Fix)
	}
	for _, l := range r.Layers() {
		switch l.Name {
		case LayerCommit, LayerPush, LayerRef, LayerPoll:
			if l.OK {
				t.Errorf("layer %q reads up on an empty machine", l.Name)
			}
		}
	}
}

func TestDoctorSeesEachWayTheGatesGoQuiet(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(*world)
		id     string
		st     Status
		has    string
	}{
		{"binary removed", func(w *world) { os.Remove(w.paths.Bin) }, "hooks.binary", Fail, "silently off"},
		{"binary not executable", func(w *world) { os.Chmod(w.paths.Bin, 0o644) }, "hooks.binary", Fail, "not executable"},
		{"binary replaced", func(w *world) { os.WriteFile(w.paths.Bin, []byte("#!/bin/sh\nexit 0\n"), 0o755) }, "hooks.binary", Warn, "not the one that was installed"},
		{"binary broken", func(w *world) { os.WriteFile(w.paths.Bin, []byte("#!/bin/sh\nexit 3\n"), 0o755); w.rehash() }, "hooks.binary", Fail, "does not run"},
		{"hook command edited", func(w *world) {
			gitOut(w.t, w.dir, "config", "--file", w.gitconfig, "--replace-all", "hook.keyguard-reftx.command", "true")
		}, "hooks.reftx", Fail, "different command"},
		{"hook event moved", func(w *world) {
			gitOut(w.t, w.dir, "config", "--file", w.gitconfig, "--replace-all", "hook.keyguard-prepush.event", "post-commit")
		}, "hooks.prepush", Fail, "listens for post-commit"},
		{"hook switched off", func(w *world) {
			gitOut(w.t, w.dir, "config", "--file", w.gitconfig, "hook.keyguard-precommit.enabled", "false")
		}, "hooks.precommit", Fail, "switched off"},
		{"hook removed", func(w *world) {
			gitOut(w.t, w.dir, "config", "--file", w.gitconfig, "--remove-section", "hook.keyguard-prepush")
		}, "hooks.prepush", Fail, "not in"},
		{"guard unregistered", func(w *world) { os.Remove(filepath.Join(w.home, ".claude", "settings.json")) }, "guard.claude", Warn, "not registered"},
		{"agent unloaded", func(w *world) { delete(w.run.loaded, LabelPoll) }, "launchd.poll", Fail, "not loaded"},
		{"plist edited", func(w *world) { os.WriteFile(filepath.Join(w.launch, LabelDeep+".plist"), []byte("<plist/>"), 0o644) }, "launchd.deep", Warn, "differs"},
		{"plist gone", func(w *world) { os.Remove(filepath.Join(w.launch, LabelPoll+".plist")) }, "launchd.poll", Fail, "no plist"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := healthyWorld(t)
			tc.break_(w)
			r := w.doctor()
			wantCheck(t, r, tc.id, tc.st, tc.has)
			if r.Healthy {
				t.Error("the report says healthy")
			}
		})
	}
}

// rehash makes the manifest agree with the binary on disk, so a test about "does it run"
// is not also a test about "is it the installed one".
func (w *world) rehash() {
	w.t.Helper()
	m, err := LoadManifest(w.paths)
	mustf(w.t, err, "manifest")
	m.Binary.SHA256 = mustHash(w.t, w.paths.Bin)
	b, _ := json.Marshal(m)
	mustf(w.t, os.WriteFile(ManifestPath(w.paths), b, 0o600), "write manifest")
}

func TestDoctorPollAge(t *testing.T) {
	for _, tc := range []struct {
		ago  time.Duration
		st   Status
		kind string
	}{
		{2 * time.Minute, OK, "poll"},
		{8 * time.Minute, OK, "poll"},
		{15 * time.Minute, Warn, "poll"},
		{45 * time.Minute, Fail, "poll"},
		{3 * time.Hour, Fail, "poll"},
		{3 * 24 * time.Hour, Fail, "deep"},
	} {
		w := healthyWorld(t)
		// healthyWorld wrote a 5 min record; replace it with the case's.
		ents, _ := os.ReadDir(w.paths.Runs)
		for _, e := range ents {
			os.Rename(filepath.Join(w.paths.Runs, e.Name()), filepath.Join(w.dir, e.Name()))
		}
		w.runRecord(tc.kind, tc.ago)
		// Newer records of kinds that are not scans (a publish check, a selftest) must not count.
		w.runRecord("publish-check", time.Second)
		r := w.doctor()
		c, _ := r.check("sweep.age")
		if c.Status != tc.st {
			t.Errorf("last scan %s ago (%s): %s %q, want %s", tc.ago, tc.kind, c.Status, c.Summary, tc.st)
		}
		if tc.st != OK && c.Fix == "" {
			t.Errorf("no fix named at %s", tc.ago)
		}
	}
}

func TestDoctorTreatsALiveLockAsARunInProgress(t *testing.T) {
	w := healthyWorld(t)
	ents, _ := os.ReadDir(w.paths.Runs)
	for _, e := range ents {
		os.Rename(filepath.Join(w.paths.Runs, e.Name()), filepath.Join(w.dir, e.Name()))
	}
	w.runRecord("deep", 30*time.Hour) // stale on its own
	mustf(t, os.WriteFile(w.paths.Lock, []byte("pid="+itoa(os.Getpid())+"\ntoken=x\nstarted=2026-11-03T09:00:00Z\n"), 0o600), "lock")
	wantCheck(t, w.doctor(), "sweep.age", OK, "a run is in progress")

	// A lock whose owner is gone does not excuse a stale scan.
	mustf(t, os.WriteFile(w.paths.Lock, []byte("pid=999999\ntoken=x\nstarted=2026-11-03T09:00:00Z\n"), 0o600), "lock")
	wantCheck(t, w.doctor(), "sweep.age", Fail, "ago")
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestDoctorEngines(t *testing.T) {
	t.Run("a different binary fails, and a different version name alone warns", func(t *testing.T) {
		w := healthyWorld(t)
		cfg, _ := LoadConfig(w.paths, w.home)
		p := cfg.Pins["betterleaks"]
		cfg.Pins["betterleaks"] = Pin{Version: "0.0.1", SHA256: p.SHA256}
		cfg.Pins["gitleaks"] = Pin{Version: cfg.Pins["gitleaks"].Version, SHA256: "0000"}
		mustf(t, cfg.Save(w.paths), "save")
		r := w.doctor()
		c := wantCheck(t, r, "engine.betterleaks", Warn, "changed from 0.0.1 to")
		if !strings.Contains(c.Detail, "fail open") {
			t.Errorf("the warning should say why drift matters: %s", c.Detail)
		}
		// The engine refuses to start, so this one is a failure and says which hashes differ.
		c = wantCheck(t, r, "engine.gitleaks", Fail, "is not the binary that was pinned (pinned 0000")
		if !strings.Contains(c.Fix, "keyguard engines pin gitleaks") || !strings.Contains(c.Detail, "will not run") {
			t.Errorf("the failure names no deliberate way back: %+v", c)
		}
		for _, l := range r.Layers() {
			if l.Name == LayerEngines && l.OK {
				t.Error("the engines layer reads up with a pinned binary that changed")
			}
		}
	})
	t.Run("a missing primary engine fails, a missing optional one warns", func(t *testing.T) {
		w := healthyWorld(t)
		cfg, _ := LoadConfig(w.paths, w.home)
		cfg.Engines["betterleaks"] = filepath.Join(w.dir, "nope", "betterleaks")
		cfg.Engines["gitleaks"] = filepath.Join(w.dir, "nope", "gitleaks")
		mustf(t, cfg.Save(w.paths), "save")
		r := w.doctor()
		wantCheck(t, r, "engine.betterleaks", Fail, "not installed")
		wantCheck(t, r, "engine.gitleaks", Warn, "not installed")
		for _, l := range r.Layers() {
			if l.Name == LayerCommit && l.OK {
				t.Error("the commit gate reads up with no regex engine")
			}
		}
	})
	t.Run("trufflehog's self-update leftover fails until it is moved aside", func(t *testing.T) {
		w := healthyWorld(t)
		cfg, _ := LoadConfig(w.paths, w.home)
		// Beside the pinned copy, in the machine's own bin and never anywhere shared: a test once
		// wrote through a symlink and replaced the real trufflehog.
		lock := filepath.Join(filepath.Dir(cfg.Engines["trufflehog"]), "trufflehog-updates.lock")
		if _, err := os.Lstat(lock); err == nil {
			t.Fatalf("%s already exists; a test must not write over something it did not make", lock)
		}
		mustf(t, os.WriteFile(lock, nil, 0o600), "lock")
		c := wantCheck(t, w.doctor(), "engine.trufflehog.updates", Fail, "updated itself")
		if !strings.Contains(c.Fix, "mv ") || strings.Contains(c.Fix, "rm ") {
			t.Errorf("the fix should move the lock aside and never remove it: %s", c.Fix)
		}
	})
	t.Run("an engine pinned where a package manager can replace it warns", func(t *testing.T) {
		w := newWorld(t)
		w.install(func(o *Options) { o.InPlace = true })
		wantCheck(t, w.doctor(), "engine.betterleaks", Warn, "pinned where a package manager can replace it")
	})
}

func TestDoctorDoesNotNagAboutAnEngineNoTierUses(t *testing.T) {
	w := healthyWorld(t)
	cfg, _ := LoadConfig(w.paths, w.home)
	cfg.Engines["titus"] = filepath.Join(w.dir, "nope", "titus")
	mustf(t, cfg.Save(w.paths), "save")
	c := wantCheck(t, w.doctor(), "engine.titus", OK, "no tier uses it")
	_ = c
	// Put it in a tier and its absence is a warning again.
	cfg.Tiers[TierDeep] = append(cfg.Tiers[TierDeep], "titus")
	mustf(t, cfg.Save(w.paths), "save")
	wantCheck(t, w.doctor(), "engine.titus", Warn, "not installed")
}

func TestDoctorKnownStore(t *testing.T) {
	t.Run("loose permissions fail and the fix is chmod", func(t *testing.T) {
		w := healthyWorld(t)
		salt := filepath.Join(w.paths.Known, "salt")
		mustf(t, os.Chmod(salt, 0o644), "chmod")
		c := wantCheck(t, w.doctor(), "known.perms", Fail, "readable by others")
		if !strings.Contains(c.Detail, "state/known/salt is 0644") || !strings.Contains(c.Fix, "chmod 600 "+salt) {
			t.Errorf("detail %q fix %q", c.Detail, c.Fix)
		}
	})
	t.Run("a data directory left open is a warning while the key files stay private", func(t *testing.T) {
		w := healthyWorld(t)
		mustf(t, os.Chmod(w.paths.State, 0o755), "chmod") // what the bootstrap script left on this Mac
		c := wantCheck(t, w.doctor(), "known.perms", Warn, "open to other users")
		if !strings.Contains(c.Fix, "chmod 700 "+w.paths.State) || strings.Contains(c.Fix, "salt") {
			t.Errorf("the fix should name only what is wrong: %q", c.Fix)
		}
		mustf(t, os.Chmod(w.paths.State, 0o700), "chmod back")
		// The directory that holds the salt is key material.
		mustf(t, os.Chmod(w.paths.Known, 0o755), "chmod known")
		wantCheck(t, w.doctor(), "known.perms", Fail, "readable by others")
	})
	t.Run("a store keyed by another salt fails", func(t *testing.T) {
		w := healthyWorld(t)
		mustf(t, os.WriteFile(filepath.Join(w.paths.Known, "salt"), make([]byte, 40), 0o600), "salt")
		wantCheck(t, w.doctor(), "known.store", Fail, "does not load")
	})
	t.Run("a store that does not parse fails", func(t *testing.T) {
		w := healthyWorld(t)
		mustf(t, os.WriteFile(filepath.Join(w.paths.Known, "known.json"), []byte("{nope"), 0o600), "write")
		wantCheck(t, w.doctor(), "known.store", Fail, "cannot be read")
	})
	t.Run("counts are shown", func(t *testing.T) {
		w := healthyWorld(t)
		c := wantCheck(t, w.doctor(), "known.store", OK, "1 secrets learned")
		if !strings.Contains(c.Summary, "forms") {
			t.Error(c.Summary)
		}
	})
}

func TestDoctorStateMirrorsAndSelftest(t *testing.T) {
	t.Run("corrupt state file", func(t *testing.T) {
		w := healthyWorld(t)
		mustf(t, os.WriteFile(w.paths.Findings, []byte("{\"secrets\":["), 0o600), "write")
		wantCheck(t, w.doctor(), "state.files", Fail, "findings.json")
	})
	t.Run("missing mirror", func(t *testing.T) {
		w := healthyWorld(t)
		m, _ := mirror.New(mirror.Config{Root: w.paths.Mirrors})
		os.Rename(m.Path(core.Source{ID: "github.com/o/n", Kind: "repo", Owner: "o", Name: "n"}), filepath.Join(w.dir, "moved.git"))
		wantCheck(t, w.doctor(), "mirrors", Warn, "1 of 1 watched sources have none")
	})
	t.Run("a missing wiki is not a missing mirror", func(t *testing.T) {
		w := healthyWorld(t)
		srcs, _ := inventory.LoadSnapshot(w.paths.Inventory)
		srcs = append(srcs, core.Source{ID: "github.com/o/n.wiki", Kind: "wiki", Owner: "o", Name: "n.wiki", Visibility: core.Public})
		mustf(t, inventory.SaveSnapshot(w.paths.Inventory, srcs, w.clock), "snapshot")
		wantCheck(t, w.doctor(), "mirrors", OK, "mirrors for 2 watched sources")
	})
	t.Run("a private repo has no mirror by design", func(t *testing.T) {
		w := healthyWorld(t)
		srcs, _ := inventory.LoadSnapshot(w.paths.Inventory)
		srcs = append(srcs, core.Source{ID: "github.com/o/closed", Kind: "repo", Owner: "o", Name: "closed", Visibility: core.Private})
		mustf(t, inventory.SaveSnapshot(w.paths.Inventory, srcs, w.clock), "snapshot")
		wantCheck(t, w.doctor(), "mirrors", OK, "1 private left alone")
	})
	t.Run("the doctor does not make the mirror directory", func(t *testing.T) {
		w := healthyWorld(t)
		mustf(t, os.Rename(filepath.Join(w.paths.Root, "cache"), filepath.Join(w.dir, "cache-moved")), "move the cache away")
		wantCheck(t, w.doctor(), "mirrors", Warn, "have none yet")
		if _, err := os.Stat(w.paths.Mirrors); err == nil {
			t.Fatal("the doctor wrote: it made the mirror root")
		}
	})
	t.Run("no inventory yet", func(t *testing.T) {
		w := healthyWorld(t)
		os.Rename(w.paths.Inventory, filepath.Join(w.dir, "inv.json"))
		wantCheck(t, w.doctor(), "mirrors", Warn, "no inventory")
	})
	t.Run("selftest stale and failed", func(t *testing.T) {
		w := healthyWorld(t)
		w.selftestRecord(true, 40*time.Hour)
		wantCheck(t, w.doctor(), "selftest.last", Warn, "40.0 h ago")
		w.selftestRecord(false, time.Hour)
		wantCheck(t, w.doctor(), "selftest.last", Fail, "failed: commit gate")
	})
}

func TestDoctorQuickStartsNothing(t *testing.T) {
	w := healthyWorld(t)
	var calls []string
	inner := w.run.run
	rec := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return inner(ctx, name, args...)
	}
	r := w.doctor(func(o *DoctorOptions) { o.Run = rec; o.Quick = true })
	if !r.Quick || !r.Healthy {
		t.Fatalf("quick doctor on a healthy machine: %+v", ids(r))
	}
	for _, c := range calls {
		if strings.HasPrefix(c, "gh ") || strings.HasPrefix(c, w.paths.Bin) {
			t.Errorf("quick mode ran %q", c)
		}
	}
	if _, ok := r.check("gh.auth"); ok {
		t.Error("quick mode checked gh")
	}
}

func TestDoctorGHAuthNeverKeepsTheToken(t *testing.T) {
	w := healthyWorld(t)
	token := "ghp_" + randStr(t, alnum, 36)
	var seen []string
	r := w.doctor(func(o *DoctorOptions) {
		o.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name == "gh" {
				seen = append(seen, strings.Join(args, " "))
				if args[len(args)-1] == "alt-builds" {
					return nil, errors.New("no oauth token found for alt-builds")
				}
				return []byte(token + "\n"), nil
			}
			return w.run.run(ctx, name, args...)
		}
	})
	c := wantCheck(t, r, "gh.auth", Fail, "alt-builds")
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), token) || strings.Contains(c.Detail, token) {
		t.Fatal("the token reached the report")
	}
	for _, s := range seen {
		if !strings.HasPrefix(s, "auth token --user ") {
			t.Errorf("doctor ran gh %s", s)
		}
	}
}

func TestDoctorBadConfigIsAFindingNotACrash(t *testing.T) {
	w := healthyWorld(t)
	mustf(t, os.WriteFile(w.paths.Config, []byte("{oops"), 0o600), "write")
	r := w.doctor()
	wantCheck(t, r, "config", Fail, "does not parse")
	// And the checks that follow still ran, on the defaults.
	if _, ok := r.check("engine.betterleaks"); !ok {
		t.Error("the doctor stopped at the bad config")
	}
}

func TestDoctorOldGit(t *testing.T) {
	w := healthyWorld(t)
	old := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "git" {
			if len(args) == 1 && args[0] == "--version" {
				return []byte("git version 2.53.1\n"), nil
			}
		}
		return w.run.run(ctx, name, args...)
	}
	wantCheck(t, w.doctor(func(o *DoctorOptions) { o.Run = old }), "git.version", Fail, "ignores config-based hooks")
}

func TestHumanAge(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second: "30 s", 5 * time.Minute: "5 min", 3 * time.Hour: "3.0 h", 72 * time.Hour: "3 days", -time.Minute: "in the future (the clock moved)",
	} {
		if got := humanAge(d); got != want {
			t.Errorf("humanAge(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestDoctorWithRealEngines(t *testing.T) {
	w := newWorld(t)
	t.Setenv("PATH", w.origPath) // the real engines, not the four tiny ones
	realEnginesOnPath(t)
	// Every engine on this Mac is copied into the machine's bin and pinned there, byte for byte.
	w.install()
	r := w.doctor(func(o *DoctorOptions) { o.Probe = RealProbe })
	cfg, _ := LoadConfig(w.paths, w.home)
	for _, name := range []string{"betterleaks", "gitleaks", "trufflehog", "titus"} {
		pin := cfg.Pins[name]
		if pin.Version == "" || len(pin.SHA256) != 64 {
			t.Errorf("%s: install pinned %+v", name, pin)
		}
		if want := EnginePath(w.paths, name, pin.Version); cfg.Engines[name] != want {
			t.Errorf("%s runs from %s, want its pinned copy %s", name, cfg.Engines[name], want)
		}
		if sum, _ := hashFile(cfg.Engines[name]); sum != pin.SHA256 {
			t.Errorf("%s: the copy is not the bytes that were pinned", name)
		}
		wantCheck(t, r, "engine."+name, OK, name+" "+pin.Version)
	}
}

// The catalog is what `doctor capabilities` tells an agent the doctor looks at. It must be what
// the doctor really does, in both modes.
func TestCatalogIsWhatTheDoctorRuns(t *testing.T) {
	w := healthyWorld(t)
	catalog := Catalog()
	if len(catalog) < 20 {
		t.Fatalf("catalog has %d entries", len(catalog))
	}
	seen := map[string]bool{}
	for _, c := range catalog {
		if seen[c.ID] || c.ID == "" || c.Looks == "" {
			t.Errorf("catalog entry %+v is duplicated or has no description", c)
		}
		seen[c.ID] = true
	}

	ran := func(r Report) map[string]bool {
		m := map[string]bool{}
		for _, c := range r.Checks {
			if m[c.ID] {
				t.Errorf("the doctor ran %s twice", c.ID)
			}
			m[c.ID] = true
		}
		return m
	}
	full, quick := ran(w.doctor()), ran(w.doctor(func(o *DoctorOptions) { o.Quick = true }))
	for _, c := range catalog {
		if !full[c.ID] && !c.Optional {
			t.Errorf("the catalog lists %s but a full run never produced it", c.ID)
		}
		if c.Optional && !quick[c.ID] {
			continue // appears only when its condition holds
		}
		if got := quick[c.ID]; got != c.Quick {
			t.Errorf("%s: catalog says quick=%v, a --quick run produced it=%v", c.ID, c.Quick, got)
		}
	}
	for id := range full {
		if !seen[id] {
			t.Errorf("the doctor produced %s, which the catalog does not list", id)
		}
	}
	for id := range quick {
		if !seen[id] {
			t.Errorf("--quick produced %s, which the catalog does not list", id)
		}
	}
	// Every fix the doctor can name for a catalogued check is one the capabilities command lists.
	fixers := Fixers()
	for _, want := range []string{"keyguard install", "keyguard learn", "keyguard poll", "keyguard selftest", "keyguard sync"} {
		if !slices.Contains(fixers, want) {
			t.Errorf("Fixers() lacks %q: %v", want, fixers)
		}
	}
}

func TestTriageFoldsAReportIntoOneAnswer(t *testing.T) {
	healthy := healthyWorld(t).doctor().Triage()
	if !healthy.Healthy || len(healthy.Findings) != 0 || healthy.Recommended != "" || !strings.HasPrefix(healthy.Summary, "healthy") {
		t.Errorf("healthy triage: %+v", healthy)
	}
	b, _ := json.Marshal(healthy)
	if strings.Contains(string(b), "null") {
		t.Errorf("an agent iterating the lists must get [] and never null: %s", b)
	}

	w := newWorld(t)
	tr := w.doctor().Triage()
	if tr.Healthy || tr.SchemaVersion != DoctorSchemaVersion || tr.Capabilities != "keyguard doctor capabilities" {
		t.Fatalf("triage: %+v", tr)
	}
	// Failures come before warnings, and the fixes are listed once each, most urgent first.
	seenWarn := false
	for _, c := range tr.Findings {
		if c.Status == OK {
			t.Errorf("an ok check in the findings: %s", c.ID)
		}
		if c.Status == Warn {
			seenWarn = true
		} else if seenWarn {
			t.Errorf("failure %s listed after a warning", c.ID)
		}
	}
	if len(tr.Actions) == 0 || tr.Recommended != tr.Actions[0] || tr.Recommended != "keyguard install" {
		t.Errorf("an empty machine should recommend install first: %q from %v", tr.Recommended, tr.Actions)
	}
	dup := map[string]bool{}
	for _, a := range tr.Actions {
		if dup[a] || strings.HasPrefix(a, "! ") {
			t.Errorf("action %q is duplicated or belongs to the user", a)
		}
		dup[a] = true
	}
	if len(tr.NeedsUser) != 1 || !strings.HasPrefix(tr.NeedsUser[0], "! f=") {
		t.Errorf("registering the guard edits Claude Code's settings and is the user's to run: %v", tr.NeedsUser)
	}
	if !strings.Contains(tr.Summary, "failing") {
		t.Errorf("summary: %q", tr.Summary)
	}
}

func TestDoctorFlagsAnIMessageTargetThatCannotWork(t *testing.T) {
	for target, want := range map[string]Status{
		"":              OK,
		"+15555550100":  OK,
		"someone@e.com": OK,
		"call me":       Warn,
		"5555550100":    Warn, // a bare number has no country code; imsg would guess
		"+1 (555":       Warn,
	} {
		w := healthyWorld(t)
		cfg, err := LoadConfig(w.paths, w.home)
		mustf(t, err, "config")
		cfg.Notify.IMessageTo = target
		mustf(t, cfg.Save(w.paths), "save")
		c, ok := w.doctor().check("notify")
		if !ok {
			t.Fatal("no notify check")
		}
		if c.Status != want {
			// notify.New decides what is a valid target; the doctor must agree with it exactly.
			t.Errorf("target %q: %s %q, want %s", target, c.Status, c.Summary, want)
		}
		if c.Status == Warn && (c.Fix == "" || strings.Contains(c.Summary+c.Detail, target)) {
			t.Errorf("target %q: a warning must name the fix and never echo the target: %+v", target, c)
		}
	}
}
