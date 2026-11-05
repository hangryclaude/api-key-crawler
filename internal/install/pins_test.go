package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyguard/internal/engines"
)

// STEAL P0-01. Install copies each engine into the data root as <name>-<version>, records the
// hash of the copy, and from then on a binary that is not the pinned one does not run.

func fakeHash(t *testing.T, w *world, name string) string {
	t.Helper()
	return mustHash(t, filepath.Join(w.fakebin, name))
}

func TestInstallCopiesEachEngineAndPinsTheCopy(t *testing.T) {
	w := newWorld(t)
	res := w.install()
	cfg, err := LoadConfig(w.paths, w.home)
	mustf(t, err, "config")
	m, err := LoadManifest(w.paths)
	mustf(t, err, "manifest")
	for _, name := range engines.Names {
		want := EnginePath(w.paths, name, "9.9.9")
		if want != filepath.Join(w.paths.Root, "bin", name+"-9.9.9") {
			t.Fatalf("the pinned copy of %s is named %s", name, want)
		}
		if cfg.Engines[name] != want {
			t.Errorf("%s: config.json points at %s, want the pinned copy %s", name, cfg.Engines[name], want)
		}
		fi, err := os.Lstat(want)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o755 {
			t.Errorf("%s: the copy is %v %v, want a regular file, mode 0755", name, fi, err)
		}
		sum := fakeHash(t, w, name)
		if got := mustHash(t, want); got != sum {
			t.Errorf("%s: the copy is not byte for byte the engine it was made from", name)
		}
		if pin := cfg.Pins[name]; pin.Version != "9.9.9" || pin.SHA256 != sum {
			t.Errorf("%s: pin %+v, want 9.9.9 and the copy's hash", name, pin)
		}
		if rec := m.Engines[name]; rec.Path != want || rec.SHA256 != sum {
			t.Errorf("%s: the install record says %+v, so uninstall could not undo it", name, rec)
		}
		// And the engine built from this config is allowed to run.
		e, err := engines.New(name, cfg.Engines[name], nopFP{}, cfg.EngineOptions(w.paths)...)
		mustf(t, err, "engine")
		if err := engines.CheckPin(e); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	var copied int
	for _, a := range res.Actions {
		if a.Step == "engine" && a.Change == "created" {
			copied++
		}
	}
	if copied != 4 {
		t.Errorf("the first install reports %d engines copied, want 4: %+v", copied, res.Actions)
	}
	if res.Snippet == "" || !strings.Contains(res.Snippet, GuardMatcher) || !strings.Contains(res.Snippet, guardCommand(w.paths.Bin)) {
		t.Errorf("install does not show the settings it would add: %q", res.Snippet)
	}
}

// The engines it was made from are read and nothing more: a Homebrew binary, or a symlink like
// titus's, is never written through.
func TestInstallOnlyReadsTheEnginesItCopies(t *testing.T) {
	w := newWorld(t)
	// titus is a symlink on this Mac. Make it one here, to a file the test owns.
	target := filepath.Join(w.dir, "elsewhere", "titus-real")
	mustf(t, os.MkdirAll(filepath.Dir(target), 0o755), "mkdir")
	mustf(t, os.Rename(filepath.Join(w.fakebin, "titus"), target), "move")
	mustf(t, os.Symlink(target, filepath.Join(w.fakebin, "titus")), "link")
	before := map[string]string{}
	for _, name := range engines.Names {
		before[name] = fakeHash(t, w, name)
	}
	targetBefore := mustHash(t, target)

	w.install()

	for _, name := range engines.Names {
		if got := fakeHash(t, w, name); got != before[name] {
			t.Errorf("%s changed during the install", name)
		}
	}
	if fi, err := os.Lstat(filepath.Join(w.fakebin, "titus")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the titus link was replaced: %v %v", fi, err)
	}
	if mustHash(t, target) != targetBefore {
		t.Error("what titus links to was written")
	}
	copyPath := EnginePath(w.paths, "titus", "9.9.9")
	if fi, err := os.Lstat(copyPath); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("the pinned titus should be a regular file, not another link: %v %v", fi, err)
	}
	if mustHash(t, copyPath) != targetBefore {
		t.Error("the pinned titus is not the bytes the link led to")
	}
}

// A repeated install is a no-op for the copies, and it is not a way to accept a binary nobody
// looked at: a copy that no longer matches its pin is left as it is and keeps the pin it had.
func TestInstallDoesNotAcceptACopyThatChanged(t *testing.T) {
	w := newWorld(t)
	w.install()
	cfg, _ := LoadConfig(w.paths, w.home)
	pinned := cfg.Pins["gitleaks"]
	copyPath := cfg.Engines["gitleaks"]
	changed := []byte("#!/bin/sh\necho 'gitleaks version 9.9.9'\n# somebody was here\n")
	mustf(t, os.WriteFile(copyPath, changed, 0o755), "tamper")

	res := w.install()

	cfg, _ = LoadConfig(w.paths, w.home)
	if cfg.Pins["gitleaks"] != pinned {
		t.Errorf("install accepted the changed copy: pin is now %+v, was %+v", cfg.Pins["gitleaks"], pinned)
	}
	if b, _ := os.ReadFile(copyPath); string(b) != string(changed) {
		t.Error("install touched the changed copy: it should be left for a person to look at")
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "keyguard engines pin gitleaks") {
		t.Errorf("install did not say how to pin it on purpose: %v", res.Warnings)
	}
	e, _ := engines.New("gitleaks", copyPath, nopFP{}, cfg.EngineOptions(w.paths)...)
	var pe *engines.PinError
	if err := engines.CheckPin(e); !errors.As(err, &pe) {
		t.Errorf("a changed pinned copy must not run, CheckPin said %v", err)
	}
	if e.Version() != "" {
		t.Error("a binary that is not the pinned one was started to ask its version")
	}
}

// A different binary under a pinned name is moved aside, never overwritten; the same bytes are a no-op.
func TestPinEngineMovesADifferentBinaryAsideAndReusesTheSame(t *testing.T) {
	w := newWorld(t)
	w.install()
	src := filepath.Join(w.fakebin, "betterleaks")
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

	dst, pin, created, err := PinEngine(w.paths, "betterleaks", src, now)
	mustf(t, err, "pin same")
	if created || dst != EnginePath(w.paths, "betterleaks", "9.9.9") || pin.SHA256 != fakeHash(t, w, "betterleaks") {
		t.Errorf("the same bytes: created=%v dst=%s pin=%+v", created, dst, pin)
	}

	other := filepath.Join(w.dir, "other-betterleaks")
	mustf(t, os.WriteFile(other, []byte("#!/bin/sh\necho 'betterleaks version 9.9.9'\n# a different build\n"), 0o755), "write")
	_, pin2, created, err := PinEngine(w.paths, "betterleaks", other, now)
	mustf(t, err, "pin other")
	if !created || pin2.SHA256 == pin.SHA256 || mustHash(t, dst) != pin2.SHA256 {
		t.Errorf("a different build under the same version: created=%v pin=%+v", created, pin2)
	}
	aside, _ := filepath.Glob(filepath.Join(SupersededDir(w.paths, now), "betterleaks-9.9.9*"))
	if len(aside) != 1 || mustHash(t, aside[0]) != pin.SHA256 {
		t.Errorf("the pinned copy it replaced was not kept: %v", aside)
	}

	// A binary that says no version has nothing to name its copy after; one that is not
	// executable is not an engine.
	mute := filepath.Join(w.dir, "mute")
	mustf(t, os.WriteFile(mute, []byte("#!/bin/sh\necho hello\n"), 0o755), "write mute")
	if _, _, _, err := PinEngine(w.paths, "betterleaks", mute, now); err == nil || !strings.Contains(err.Error(), "does not say its version") {
		t.Errorf("a binary with no version: %v", err)
	}
	flat := filepath.Join(w.dir, "flat")
	mustf(t, os.WriteFile(flat, []byte("x"), 0o644), "write flat")
	if _, _, _, err := PinEngine(w.paths, "betterleaks", flat, now); err == nil {
		t.Error("a file that is not executable was pinned")
	}
}

func TestInstallInPlacePinsWhereTheEngineIs(t *testing.T) {
	w := newWorld(t)
	w.install(func(o *Options) { o.InPlace = true })
	cfg, _ := LoadConfig(w.paths, w.home)
	for _, name := range engines.Names {
		if cfg.Engines[name] != filepath.Join(w.fakebin, name) {
			t.Errorf("%s: %s, want it where it was found", name, cfg.Engines[name])
		}
		if cfg.Pins[name].SHA256 != fakeHash(t, w, name) {
			t.Errorf("%s: pinned %+v", name, cfg.Pins[name])
		}
	}
	if left, _ := filepath.Glob(filepath.Join(w.paths.BinDir, "*-9.9.9")); len(left) != 0 {
		t.Errorf("copies were made anyway: %v", left)
	}
}

// Install makes what a hook needs to find in place: the keyring (a hook may never mint one), the
// engines' private scratch directory, the directory for the pinned copies.
func TestInstallMakesTheKeyringTheScratchAndTheBinDir(t *testing.T) {
	w := newWorld(t)
	w.install()
	salt := filepath.Join(w.paths.Known, "salt")
	if fi, err := os.Stat(salt); err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != 40 {
		t.Errorf("salt: %v %v", fi, err)
	}
	for _, d := range []string{w.paths.Known, w.paths.Tmp, w.paths.BinDir} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v, want a private directory", d, fi, err)
		}
	}
	before := mustHash(t, salt)
	w.install()
	if mustHash(t, salt) != before {
		t.Error("a second install changed the salt, which would orphan every learned hash")
	}
}

func TestInstallDoesNotMintASaltBesideALearnedStore(t *testing.T) {
	w := newWorld(t)
	mustf(t, os.MkdirAll(w.paths.Known, 0o700), "mkdir")
	mustf(t, os.WriteFile(w.paths.KnownStore, []byte(`{"version":1}`), 0o600), "known.json")
	res := w.install()
	if _, err := os.Stat(filepath.Join(w.paths.Known, "salt")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a salt was made beside a learned store: %v", err)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "orphan every learned hash") {
		t.Errorf("no warning: %v", res.Warnings)
	}
}

func TestUninstallMovesThePinnedCopiesAside(t *testing.T) {
	w := newWorld(t)
	w.install()
	cfg, _ := LoadConfig(w.paths, w.home)
	sums := map[string]string{}
	for name, p := range cfg.Engines {
		sums[name] = mustHash(t, p)
	}
	res := w.uninstall()
	var moved int
	for _, a := range res.Actions {
		if a.Step == "engine" && a.Change == "moved" {
			moved++
		}
	}
	if moved != 4 {
		t.Errorf("uninstall moved %d engines, want 4: %+v", moved, res.Actions)
	}
	for name, p := range cfg.Engines {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: the pinned copy is still in bin", name)
		}
		found, _ := filepath.Glob(filepath.Join(w.paths.Root, ".uninstalled", "*", filepath.Base(p)))
		if len(found) != 1 || mustHash(t, found[0]) != sums[name] {
			t.Errorf("%s: the copy was not moved aside intact: %v", name, found)
		}
	}
	// The engines it was copied from were never part of the install.
	for _, name := range engines.Names {
		if _, err := os.Stat(filepath.Join(w.fakebin, name)); err != nil {
			t.Errorf("uninstall touched %s where it was found: %v", name, err)
		}
	}
	// Installing again after an uninstall brings the copies back from where the engines are.
	w.install()
	cfg2, _ := LoadConfig(w.paths, w.home)
	for name, p := range cfg2.Engines {
		if mustHash(t, p) != sums[name] {
			t.Errorf("%s: reinstall did not restore the pinned copy", name)
		}
	}
}

// titus builds a Hyperscan cache the first time it runs, 2.7 s of it. Install builds it when a
// tier uses titus, so the first hook that does is not the one that pays; with no tier using it
// nothing is started.
func TestInstallBuildsTitusCacheOnlyWhenATierUsesIt(t *testing.T) {
	fakeTitus := "#!/bin/sh\ncase \"$1\" in\n  version) echo 'titus version 9.9.9';;\n  scan) mkdir -p \"$TITUS_CACHE_DIR\" && echo built > \"$TITUS_CACHE_DIR/rules.bin\"; echo '[]';;\nesac\n"
	for _, tc := range []struct {
		name   string
		inTier bool
	}{{"a tier uses titus", true}, {"no tier uses titus", false}} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			mustf(t, os.WriteFile(filepath.Join(w.fakebin, "titus"), []byte(fakeTitus), 0o755), "write titus")
			if tc.inTier {
				cfg, _ := LoadConfig(w.paths, w.home)
				cfg.Tiers[TierPoll] = append(cfg.Tiers[TierPoll], "titus")
				mustf(t, cfg.Save(w.paths), "save")
			}
			w.install(func(o *Options) { o.NoPrewarm = false })
			_, err := os.Stat(filepath.Join(w.paths.TitusCache, "rules.bin"))
			if tc.inTier && err != nil {
				t.Errorf("the rule cache was not built under the data root: %v", err)
			}
			if !tc.inTier && err == nil {
				t.Error("titus was started although no tier uses it")
			}
		})
	}
}

// A prewarm that fails (titus will not start) is a warning, not a failed install: the engine
// still works, its first scan is just slower.
func TestAFailedPrewarmIsAWarning(t *testing.T) {
	w := newWorld(t)
	mustf(t, os.WriteFile(filepath.Join(w.fakebin, "titus"), []byte("#!/bin/sh\ncase \"$1\" in version) echo 'titus version 9.9.9';; *) exit 3;; esac\n"), 0o755), "write")
	cfg, _ := LoadConfig(w.paths, w.home)
	cfg.Tiers[TierPoll] = append(cfg.Tiers[TierPoll], "titus")
	mustf(t, cfg.Save(w.paths), "save")
	o := w.opts()
	o.NoPrewarm = false
	res, err := Install(context.Background(), o)
	if err != nil {
		t.Fatalf("install failed because titus would not prewarm: %v", err)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "titus did not build its rule cache") {
		t.Errorf("no warning: %v", res.Warnings)
	}
}

// --dry-run says what would be copied and writes nothing at all.
func TestDryRunCopiesNoEngines(t *testing.T) {
	w := newWorld(t)
	before := tree(t, w.dir)
	res := w.install(func(o *Options) { o.DryRun = true })
	if d := diffTrees(before, tree(t, w.dir)); d != "" {
		t.Errorf("a dry run wrote:\n%s", d)
	}
	var would int
	for _, a := range res.Actions {
		if a.Step == "engine" && strings.Contains(a.Detail, "would copy") {
			would++
		}
	}
	if would != 4 {
		t.Errorf("the dry run names %d engine copies, want 4: %+v", would, res.Actions)
	}
}
