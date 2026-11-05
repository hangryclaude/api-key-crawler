package install

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"keyguard/rules"
)

func TestInstallWritesEverythingThenChangesNothing(t *testing.T) {
	w := newWorld(t)
	w.writeGitConfig("# the user\n[user]\n\tname = A\n")

	res := w.install(func(o *Options) { o.Pin = nil }) // the real pins: engines are started and hashed once
	if !res.Changed() {
		t.Fatal("the first install reported no change")
	}

	// The binary the hooks run is a byte-for-byte copy, executable.
	if sum, _ := hashFile(w.paths.Bin); sum != mustHash(t, w.exe) {
		t.Error("installed binary differs from the source")
	}
	if fi, err := os.Stat(w.paths.Bin); err != nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("installed binary mode: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(RulesPath(w.paths)); !bytes.Equal(b, rules.KeyguardTOML) {
		t.Error("the rules file is not the embedded rules")
	}
	// config.json exists, is private, and names the engines found on this Mac.
	fi, err := os.Stat(w.paths.Config)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("config.json: %v %v", fi, err)
	}
	cfg, err := LoadConfig(w.paths, w.home)
	if err != nil || cfg.Jobs != 8 || len(cfg.Pins) == 0 || cfg.Pins["betterleaks"].Version == "" || cfg.Pins["betterleaks"].SHA256 == "" {
		t.Errorf("config after install: %+v %v", cfg, err)
	}

	// All eight git keys are set (four hooks), and git itself reads them back (this is what a commit sees).
	for _, h := range HookSpecs {
		if got := gitOut(t, w.dir, "config", "--file", w.gitconfig, "--get", "hook."+h.name+".event"); got != h.event {
			t.Errorf("hook.%s.event = %q", h.name, got)
		}
		want := HookCommand(w.paths.Bin, h.event)
		if got := gitOut(t, w.dir, "config", "--file", w.gitconfig, "--get", "hook."+h.name+".command"); got != want {
			t.Errorf("hook.%s.command = %q, want %q", h.name, got, want)
		}
	}
	if !strings.Contains(string(w.gitConfigBytes()), "# the user") {
		t.Error("the user's own config was not kept")
	}

	// The three agents are valid plists and loaded.
	for _, label := range []string{LabelPoll, LabelDeep, LabelUpgrade} {
		plist := filepath.Join(w.launch, label+".plist")
		if out, err := exec.Command("plutil", "-lint", plist).CombinedOutput(); err != nil {
			t.Errorf("plutil -lint %s: %v %s", label, err, out)
		}
		if !w.run.isLoaded(label) {
			t.Errorf("%s was not loaded", label)
		}
	}
	m, err := LoadManifest(w.paths)
	if err != nil || m.Version != 1 || len(m.Launchd.Jobs) != 3 || len(m.Git.Keys) != 8 || len(m.Engines) != 4 || !m.Git.Existed || m.Git.OriginalCopy == "" {
		t.Errorf("manifest: %+v %v", m, err)
	}

	// A second install finds everything in place and touches nothing.
	before := tree(t, w.dir)
	w.run.reset()
	again := w.install(func(o *Options) { o.Pin = nil })
	if again.Changed() {
		t.Errorf("a repeated install changed things: %+v", again.Actions)
	}
	if n := w.run.count("bootstrap") + w.run.count("bootout"); n != 0 {
		t.Errorf("a repeated install reloaded launchd %d times", n)
	}
	if d := diffTrees(before, tree(t, w.dir)); d != "" {
		t.Errorf("a repeated install altered files:\n%s", d)
	}
}

func mustHash(t testing.TB, p string) string {
	t.Helper()
	s, err := hashFile(p)
	mustf(t, err, "hash %s", p)
	return s
}

func TestInstallUpdatesWhatChangedAndOnlyThat(t *testing.T) {
	w := newWorld(t)
	w.install()
	w.run.reset()

	// A rebuilt binary is copied over and nothing else is rewritten.
	w.setExe("#!/bin/sh\necho a newer build\n")
	res := w.install()
	var changed []string
	for _, a := range res.Actions {
		if a.Change == "updated" || a.Change == "created" {
			changed = append(changed, a.Step)
		}
	}
	if !slices.Equal(changed, []string{"binary", "config"}) && !slices.Equal(changed, []string{"binary"}) {
		// config is rewritten only if a pin moved; the binary is not an engine, so it must not.
		t.Errorf("a new binary should change the binary alone, changed: %v", changed)
	}
	if got := mustHash(t, w.paths.Bin); got != mustHash(t, w.exe) {
		t.Error("the new binary was not installed")
	}

	// A plist that someone edited is put back and reloaded.
	plist := filepath.Join(w.launch, LabelPoll+".plist")
	if err := os.WriteFile(plist, []byte("<plist/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	w.run.reset()
	w.install()
	if b, _ := os.ReadFile(plist); !strings.Contains(string(b), LabelPoll) {
		t.Error("the edited plist was not restored")
	}
	if w.run.count("bootstrap") != 1 || w.run.count("bootout") != 1 {
		t.Errorf("only the poll agent should reload: %v", w.run.calls)
	}

	// An agent that is no longer loaded is loaded again even though its file is fine.
	delete(w.run.loaded, LabelDeep)
	w.run.reset()
	w.install()
	if !w.run.isLoaded(LabelDeep) {
		t.Error("an unloaded agent was not loaded again")
	}
}

func TestUninstallRestoresTheGitConfigByteForByte(t *testing.T) {
	cases := map[string]string{
		"comments and sections":    "# my config\n[user]\n\tname = X\n\temail = x@y.z\n\n[core]\n\teditor = vim\n",
		"no final newline":         "[user]\n\tname = X",
		"crlf and odd spacing":     "[user]\r\n   name   =   X\r\n\r\n\r\n",
		"an empty file":            "",
		"an include and an alias":  "[include]\n\tpath = ~/.gitconfig.local\n[alias]\n\tco = checkout\n",
		"a hook of the users own":  "[hook \"lint\"]\n\tevent = pre-commit\n\tcommand = make lint\n",
		"keyguard's section order": "[hook \"keyguard-reftx\"]\n\tevent = something\n",
	}
	for name, original := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.writeGitConfig(original)
			w.install()
			if bytes.Equal(w.gitConfigBytes(), []byte(original)) {
				t.Fatal("install left the config alone")
			}
			res := w.uninstall()
			if got := w.gitConfigBytes(); !bytes.Equal(got, []byte(original)) {
				t.Errorf("config not restored.\nwant %q\ngot  %q\nactions %+v", original, got, res.Actions)
			}
			assertGone(t, w)
		})
	}
}

// assertGone checks every file Install wrote has left its place and nothing was deleted.
func assertGone(t *testing.T, w *world) {
	t.Helper()
	for _, p := range []string{
		w.paths.Bin, RulesPath(w.paths), ManifestPath(w.paths),
		filepath.Join(w.launch, LabelPoll+".plist"), filepath.Join(w.launch, LabelDeep+".plist"),
	} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there after uninstall", p)
		}
	}
	for _, l := range []string{LabelPoll, LabelDeep} {
		if w.run.isLoaded(l) {
			t.Errorf("%s is still loaded", l)
		}
	}
	// Moved, not deleted: the binary and the install record are in .uninstalled.
	found := map[string]bool{}
	filepath.WalkDir(filepath.Join(w.paths.Root, ".uninstalled"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			found[filepath.Base(p)] = true
		}
		return nil
	})
	for _, want := range []string{"keyguard", "keyguard.toml", "install.json", LabelPoll + ".plist", LabelDeep + ".plist"} {
		if !found[want] {
			t.Errorf("%s was not kept in .uninstalled (have %v)", want, found)
		}
	}
	// Data stays: config.json is configuration, not part of the install.
	if _, err := os.Stat(w.paths.Config); err != nil {
		t.Errorf("config.json went with the uninstall: %v", err)
	}
}

func TestUninstallWhenInstallCreatedTheGitConfig(t *testing.T) {
	w := newWorld(t)
	if _, err := os.Stat(w.gitconfig); err == nil {
		t.Fatal("setup: the config should not exist yet")
	}
	w.install()
	w.uninstall()
	if _, err := os.Stat(w.gitconfig); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a git config that install created must go aside on uninstall, got %v", err)
	}
	assertGone(t, w)
}

func TestUninstallAfterSomeoneEditedTheGitConfig(t *testing.T) {
	w := newWorld(t)
	w.writeGitConfig("[user]\n\tname = A\n")
	w.install()

	// A tool adds a section after the install. Putting the original bytes back would erase it.
	f, err := os.OpenFile(w.gitconfig, os.O_APPEND|os.O_WRONLY, 0)
	mustf(t, err, "open")
	f.WriteString("[alias]\n\tco = checkout\n")
	f.Close()

	res := w.uninstall()
	got := string(w.gitConfigBytes())
	if !strings.Contains(got, "co = checkout") || !strings.Contains(got, "name = A") {
		t.Errorf("the later edit was lost:\n%s\n%+v", got, res.Actions)
	}
	if strings.Contains(got, "keyguard") || strings.Contains(got, "[hook") {
		t.Errorf("keyguard's keys are still in the config:\n%s", got)
	}
}

func TestUninstallPutsBackWhatAKeyHeldBefore(t *testing.T) {
	w := newWorld(t)
	key := "hook.keyguard-prepush.command"
	w.writeGitConfig("[hook \"keyguard-prepush\"]\n\tcommand = echo mine\n")
	w.install()
	if got := gitOut(t, w.dir, "config", "--file", w.gitconfig, "--get", key); got == "echo mine" {
		t.Fatal("install did not replace the key")
	}
	m, _ := LoadManifest(w.paths)
	var prev []string
	for _, k := range m.Git.Keys {
		if k.Key == key {
			prev = k.Previous
		}
	}
	if !slices.Equal(prev, []string{"echo mine"}) {
		t.Fatalf("manifest forgot the earlier value: %v", prev)
	}

	// Edit the file so the byte-for-byte path is off the table and the keys are cut out one by one.
	f, _ := os.OpenFile(w.gitconfig, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("[core]\n\tpager = less\n")
	f.Close()
	w.uninstall()
	if got := gitOut(t, w.dir, "config", "--file", w.gitconfig, "--get", key); got != "echo mine" {
		t.Errorf("%s = %q after uninstall, want the old value back", key, got)
	}
	if out, _ := exec.Command("git", "config", "--file", w.gitconfig, "--get", "hook.keyguard-reftx.event").Output(); len(out) != 0 {
		t.Errorf("a key install added is still set: %s", out)
	}
}

func TestUninstallLeavesAKeyAloneThatChangedSinceInstall(t *testing.T) {
	w := newWorld(t)
	w.install()
	gitOut(t, w.dir, "config", "--file", w.gitconfig, "--replace-all", "hook.keyguard-reftx.command", "echo someone else was here")
	res := w.uninstall()
	if got := gitOut(t, w.dir, "config", "--file", w.gitconfig, "--get", "hook.keyguard-reftx.command"); got != "echo someone else was here" {
		t.Errorf("a key changed after install was overwritten: %q", got)
	}
	if !slices.ContainsFunc(res.Warnings, func(s string) bool { return strings.Contains(s, "left alone") }) {
		t.Errorf("no warning about the key left alone: %v", res.Warnings)
	}
	if out, _ := exec.Command("git", "config", "--file", w.gitconfig, "--get", "hook.keyguard-prepush.command").Output(); len(out) != 0 {
		t.Errorf("an unchanged key survived uninstall: %s", out)
	}
}

func TestUninstallWithoutAnInstallRecordChangesNothing(t *testing.T) {
	w := newWorld(t)
	w.writeGitConfig("[user]\n\tname = A\n")
	before := tree(t, w.dir)
	res := w.uninstall()
	if res.Changed() || len(res.Warnings) == 0 {
		t.Errorf("nothing was installed, yet: %+v", res)
	}
	if d := diffTrees(before, tree(t, w.dir)); d != "" {
		t.Errorf("uninstall without a record altered files:\n%s", d)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	w := newWorld(t)
	w.writeGitConfig("[user]\n\tname = A\n")
	before := tree(t, w.dir)
	res := w.install(func(o *Options) { o.DryRun = true })
	if !res.Changed() {
		t.Error("a dry run on a bare machine should report what it would do")
	}
	if d := diffTrees(before, tree(t, w.dir)); d != "" {
		t.Errorf("dry-run install altered files:\n%s", d)
	}
	if len(w.run.calls) != 0 && w.run.count("bootstrap") != 0 {
		t.Errorf("dry-run install called launchctl: %v", w.run.calls)
	}

	w.install()
	installed := tree(t, w.dir)
	res = w.uninstall(func(o *Options) { o.DryRun = true })
	if !res.Changed() {
		t.Error("a dry-run uninstall should report what it would undo")
	}
	if d := diffTrees(installed, tree(t, w.dir)); d != "" {
		t.Errorf("dry-run uninstall altered files:\n%s", d)
	}
	if !w.run.isLoaded(LabelPoll) {
		t.Error("dry-run uninstall unloaded an agent")
	}
}

func TestLaunchctlFailureLeavesAnUndoableInstall(t *testing.T) {
	w := newWorld(t)
	w.run.failBootstrap = errors.New("Bootstrap failed: 5: Input/output error")
	_, err := Install(context.Background(), w.opts())
	if err == nil || !strings.Contains(err.Error(), "launchctl bootstrap") {
		t.Fatalf("expected a launchctl error, got %v", err)
	}
	// The hooks and the binary went in before launchd failed; the record says so.
	m, merr := LoadManifest(w.paths)
	if merr != nil || len(m.Git.Keys) != 8 || m.Binary.SHA256 == "" {
		t.Fatalf("a half install left no usable record: %+v %v", m, merr)
	}
	w.uninstall()
	if _, err := os.Stat(w.paths.Bin); !errors.Is(err, os.ErrNotExist) {
		t.Error("the half-installed binary was not removed")
	}
}

func TestNoLaunchdAndNoBootstrap(t *testing.T) {
	w := newWorld(t)
	w.install(func(o *Options) { o.NoLaunchd = true })
	if _, err := os.Stat(w.launch); !errors.Is(err, os.ErrNotExist) {
		t.Error("NoLaunchd still wrote the LaunchAgents dir")
	}
	w.install(func(o *Options) { o.NoBootstrap = true })
	if _, err := os.Stat(filepath.Join(w.launch, LabelPoll+".plist")); err != nil {
		t.Error("NoBootstrap should still write the plists")
	}
	if len(w.run.loaded) != 0 || w.run.count("bootstrap") != 0 {
		t.Errorf("NoBootstrap loaded something: %v", w.run.calls)
	}
	// Uninstall of an install that never loaded the agents must not talk to launchd at all:
	// the real launchctl would unload the user's real job of the same label.
	w.run.reset()
	w.uninstall()
	if n := w.run.count("bootout"); n != 0 {
		t.Errorf("uninstall booted out %d agents that this install never loaded", n)
	}
}

func TestInstallRefusesADevNullGitConfig(t *testing.T) {
	w := newWorld(t)
	o := w.opts()
	o.GitConfig = os.DevNull
	if _, err := Install(context.Background(), o); err == nil {
		t.Fatal("install into /dev/null must be refused")
	}
}

func TestHookCommandRunsLikeGitRunsIt(t *testing.T) {
	dir := t.TempDir()
	// The command runs through sh with git's hook arguments appended; a binary that is gone
	// must be a clean no-op, never an error that stops every commit on the machine.
	missing := filepath.Join(dir, "no such dir", "it's here", "keyguard")
	for _, bin := range []string{missing, filepath.Join(dir, "plain")} {
		cmd := exec.Command("sh", "-c", HookCommand(bin, "pre-push")+` "$@"`, "hook", "origin", "https://example.invalid/x.git")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("hook with a missing binary %q failed: %v %s", bin, err, out)
		}
	}
	// And with the binary there, it is exec'd with the event and git's arguments.
	script := filepath.Join(dir, "it's a dir", "keyguard")
	if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s|' \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", HookCommand(script, "pre-push")+` "$@"`, "hook", "origin", "https://example.invalid/x.git").Output()
	if err != nil || string(out) != "hook|pre-push|origin|https://example.invalid/x.git|" {
		t.Errorf("hook ran as %q (%v)", out, err)
	}
}

func TestPlistEscapesAndPinsThePaths(t *testing.T) {
	w := newWorld(t)
	w.paths = coreAt(filepath.Join(w.dir, "a&b <root>"))
	w.install(func(o *Options) { o.NoBootstrap = true })
	for _, j := range jobsFor() {
		plist := j.file(w.launch)
		if out, err := exec.Command("plutil", "-lint", plist).CombinedOutput(); err != nil {
			t.Fatalf("plutil -lint %s: %v %s", j.label, err, out)
		}
		out, err := exec.Command("plutil", "-convert", "json", "-o", "-", plist).Output()
		mustf(t, err, "plutil convert")
		var got struct {
			Label                 string
			ProgramArguments      []string
			StartInterval         int
			StartCalendarInterval map[string]int
			EnvironmentVariables  map[string]string
			StandardOutPath       string
			StandardErrorPath     string
			RunAtLoad             bool
			Nice                  int
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatal(err)
		}
		if got.Label != j.label || got.ProgramArguments[0] != w.paths.Bin || got.ProgramArguments[1] != j.args[0] {
			t.Errorf("%s: label/args %+v", j.label, got)
		}
		if got.EnvironmentVariables["KEYGUARD_HOME"] != w.paths.Root {
			t.Errorf("%s: a root other than ~/.keyguard must be handed to the job: %v", j.label, got.EnvironmentVariables)
		}
		for _, dir := range []string{"/opt/homebrew/bin", filepath.Join(w.home, ".local", "bin")} {
			if !slices.Contains(strings.Split(got.EnvironmentVariables["PATH"], ":"), dir) {
				t.Errorf("%s: PATH lacks %s: %s", j.label, dir, got.EnvironmentVariables["PATH"])
			}
		}
		if !strings.HasPrefix(got.StandardOutPath, w.paths.Logs) || !strings.HasPrefix(got.StandardErrorPath, w.paths.Logs) {
			t.Errorf("%s: logs go outside %s: %s %s", j.label, w.paths.Logs, got.StandardOutPath, got.StandardErrorPath)
		}
		if j.label == LabelPoll && got.StartInterval != 60 {
			t.Errorf("poll runs every %d s, want 60", got.StartInterval)
		}
		if j.label == LabelUpgrade && (got.StartCalendarInterval["Weekday"] != 6 || got.StartCalendarInterval["Hour"] != 4 || got.StartCalendarInterval["Minute"] != 0 ||
			strings.Join(got.ProgramArguments[1:], " ") != "engines check-upgrade") {
			t.Errorf("upgrade runs %v at %v, want engines check-upgrade on Saturday 04:00", got.ProgramArguments[1:], got.StartCalendarInterval)
		}
		if j.label == LabelDeep && (got.StartCalendarInterval["Weekday"] != 0 || got.StartCalendarInterval["Hour"] != 3 || got.StartCalendarInterval["Minute"] != 30) {
			t.Errorf("deep runs at %v, want Sunday 03:30", got.StartCalendarInterval)
		}
	}
}

func TestInstalledRootAtHomeNeedsNoKeyguardHomeInPlist(t *testing.T) {
	w := newWorld(t)
	w.install(func(o *Options) { o.NoBootstrap = true })
	b, err := os.ReadFile(filepath.Join(w.launch, LabelPoll+".plist"))
	mustf(t, err, "read plist")
	if strings.Contains(string(b), "KEYGUARD_HOME") {
		t.Error("the default root is ~/.keyguard; the plist should not override it")
	}
}

// Dotfile managers link ~/.gitconfig to a file in a repo. Git edits through the link, and
// so must the byte-for-byte restore: replacing the link with a regular file would quietly
// disconnect the user's dotfiles from the config git reads.
func TestSymlinkedGitConfigStaysASymlink(t *testing.T) {
	w := newWorld(t)
	original := "# managed by dotfiles\n[user]\n\tname = A"
	target := filepath.Join(w.dir, "dotfiles", "gitconfig")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, w.gitconfig); err != nil {
		t.Fatal(err)
	}

	w.install()
	if fi, err := os.Lstat(w.gitconfig); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("install replaced the link with a regular file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(target); !strings.Contains(string(b), "keyguard-precommit") {
		t.Fatal("the hooks did not land in the file the link points at")
	}

	w.uninstall()
	fi, err := os.Lstat(w.gitconfig)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("uninstall replaced the link with a regular file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(target); string(b) != original {
		t.Errorf("the linked file is not back byte for byte:\n%q", b)
	}
}
