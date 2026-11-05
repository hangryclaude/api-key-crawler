package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/install"
)

// TestDoctorIsHealthyOnAFullyWiredMachine builds the whole thing the way a person would, with
// the real binary and the real engines: install, learn, a first poll, the guard registered,
// a selftest on record. launchd and gh are answered by a stand-in, since the real ones belong
// to whoever runs the tests. Then it breaks the machine one way at a time.
func TestDoctorIsHealthyOnAFullyWiredMachine(t *testing.T) {
	w := newWorld(t)
	m := w.m
	m.installFull() // the real engines, copied into the machine's bin and pinned there

	cfg, err := install.LoadConfig(w.paths, m.home)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Tiers[install.TierPoll] = []string{"betterleaks"}
	cfg.Accounts = []string{"o"} // the machine's gh is logged out, so install found none
	if err := cfg.Save(w.paths); err != nil {
		t.Fatal(err)
	}

	m.learn("OPENAI_API_KEY", fakeKey(t, "sk-proj-", 48))
	open := w.addRepo("open", core.Public)
	w.commit(open, "init", map[string]string{"README.md": "hello\n"})
	w.mustCLI("poll", "--no-daily", "--no-verify")

	bin := filepath.Join(m.root, "bin", "keyguard")
	m.write(filepath.Join(m.home, ".claude", "settings.json"),
		`{"hooks":{"PreToolUse":[{"matcher":"`+install.GuardMatcher+`","hooks":[{"type":"command","command":"`+bin+` guard claude"}]}]}}`)
	rec, _ := json.Marshal(install.SelftestRecord{At: time.Now().UTC().Format(time.RFC3339), OK: true, Layers: []install.SelftestLayer{{Name: "commit gate", OK: true}}})
	m.write(install.SelftestPath(w.paths), string(rec))
	if err := install.SaveProtection(w.paths, install.Protection{At: time.Now().UTC().Format(time.RFC3339), Headline: "GitHub protects 1 of 1 repos", Repos: 1, Public: 1, Protected: 1}); err != nil {
		t.Fatal(err)
	}

	loaded := map[string]bool{install.LabelPoll: true, install.LabelDeep: true, install.LabelUpgrade: true}
	w.seams.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "launchctl":
			if len(args) == 2 && args[0] == "print" && loaded[filepath.Base(args[1])] {
				return []byte("state = waiting\n"), nil
			}
			return nil, os.ErrNotExist
		case "gh":
			return []byte("placeholder-not-a-token\n"), nil
		}
		return install.ExecRunner(ctx, name, args...)
	}

	out, errs, code := w.cli("doctor", "--json")
	var rep install.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("doctor --json: %v\n%s\n%s", err, out, errs)
	}
	if code != 0 || !rep.Healthy {
		for _, c := range rep.Checks {
			if c.Status != install.OK {
				t.Errorf("%s %s: %s (%s) fix: %s", c.ID, c.Status, c.Summary, c.Detail, c.Fix)
			}
		}
		t.Fatalf("a fully wired machine: exit %d, %d ok, %d warnings, %d failures", code, rep.Ok, rep.Warnings, rep.Failures)
	}
	human, _, code := w.cli("doctor")
	if code != 0 || !strings.Contains(human, "0 warnings, 0 failures") || strings.Contains(human, "To fix:") {
		t.Errorf("human output of a healthy machine: %d\n%s", code, human)
	}
	if line, _, code := w.cli("doctor", "health"); code != 0 || strings.TrimSpace(line) != "healthy" {
		t.Errorf("doctor health: %d %q", code, line)
	}
	// The report page shows the same layers.
	w.mustCLI("report")
	page, _ := os.ReadFile(w.paths.Report)
	for _, layer := range []string{install.LayerCommit, install.LayerRef, install.LayerPoll} {
		if !strings.Contains(string(page), layer) {
			t.Errorf("the report does not show the %q layer", layer)
		}
	}

	// One thing at a time, and the doctor names it.
	for name, brk := range map[string]struct {
		do func()
		id string
	}{
		"an agent unloaded": {func() { delete(loaded, install.LabelDeep) }, "launchd.deep"},
		"the binary gone":   {func() { os.Rename(bin, bin+".moved") }, "hooks.binary"},
	} {
		brk.do()
		out, _, code := w.cli("doctor", "--json")
		var r install.Report
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		c, ok := findCheck(r, brk.id)
		if code != 1 || !ok || c.Status != install.Fail || c.Fix == "" {
			t.Errorf("%s: exit %d, %s: %+v", name, code, brk.id, c)
		}
	}
}

func findCheck(r install.Report, id string) (install.Check, bool) {
	for _, c := range r.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return install.Check{}, false
}
