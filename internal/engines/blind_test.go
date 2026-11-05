package engines

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/internal/fp"
	"keyguard/internal/testkit"
)

// Files that live in the repository must not be able to silence the pre-commit scan (STEAL
// P0-05, P0-12). Each of these hid a staged token from the real engine (reproduced on
// betterleaks 1.9.0 and gitleaks 8.30.1): an ignore file holding the finding's fingerprint,
// an allowlist config, a .gitattributes that makes git print "Binary files differ" for the
// file, and the engine's own allow comment on the line.

// finding is the part of an engine report these tests may read: where, not what.
type finding struct {
	Fingerprint string
}

// fingerprintOf asks the real engine what it calls the finding in wt's index, straight from the
// binary, so an ignore file can be written for it.
func fingerprintOf(t *testing.T, bin, wt string) string {
	t.Helper()
	out, err := exec.Command(bin, "git", "--pre-commit", "--staged", "--no-banner", "--no-color", "-l", "error",
		"-f", "json", "-r", "-", "--exit-code", "0", wt).Output()
	if err != nil {
		t.Fatalf("fingerprint run: %v", err)
	}
	var fs []finding
	if err := json.Unmarshal(out, &fs); err != nil || len(fs) != 1 {
		t.Fatalf("expected one finding to ignore, got %d (%v)", len(fs), err)
	}
	return fs[0].Fingerprint
}

type blinder struct {
	label string
	apply func(t *testing.T, wt, engine, bin, token string)
}

func blinders() []blinder {
	ignoreName := map[string]string{"betterleaks": ".betterleaksignore", "gitleaks": ".gitleaksignore"}
	cfgName := map[string]string{"betterleaks": ".betterleaks.toml", "gitleaks": ".gitleaks.toml"}
	allowTag := map[string]string{"betterleaks": "betterleaks:allow", "gitleaks": "gitleaks:allow"}
	ignoreFile := func(t *testing.T, wt, engine, bin, _ string) {
		fpr := fingerprintOf(t, bin, wt)
		writeLines(t, wt, ignoreName[engine], fpr)
	}
	config := func(t *testing.T, wt, engine, _, _ string) {
		writeLines(t, wt, cfgName[engine], "[extend]", "useDefault = true", "[allowlist]", `regexes = [".*"]`)
	}
	attrs := func(t *testing.T, wt, _, _, _ string) { writeLines(t, wt, ".gitattributes", "*.env -diff") }
	binaryAttr := func(t *testing.T, wt, _, _, _ string) { writeLines(t, wt, ".gitattributes", "*.env binary") }
	allow := func(t *testing.T, wt, engine, _, token string) {
		writeLines(t, wt, "b.env", "GITHUB_TOKEN="+token+" # "+allowTag[engine])
	}
	return []blinder{
		{"ignore file", ignoreFile},
		{"allowlist config", config},
		{"-diff attribute", attrs},
		{"binary attribute", binaryAttr},
		{"allow comment", allow},
		{"all of them", func(t *testing.T, wt, engine, bin, token string) {
			allow(t, wt, engine, bin, token)
			ignoreFile(t, wt, engine, bin, token)
			config(t, wt, engine, bin, token)
			attrs(t, wt, engine, bin, token)
		}},
	}
}

func TestRepoFilesCannotBlindThePreCommitScan(t *testing.T) {
	f := getFixture(t)
	for _, name := range []string{"betterleaks", "gitleaks"} {
		for _, b := range append([]blinder{{"nothing (control)", func(*testing.T, string, string, string, string) {}}}, blinders()...) {
			t.Run(name+"/"+b.label, func(t *testing.T) {
				bin := needEngine(t, name)
				e := newEngine(t, name, f.kr)
				resetAudit()
				wt := worktree(t)
				token := fake("github")
				writeLines(t, wt, "b.env", "GITHUB_TOKEN="+token)
				gitIn(wt, nil, "add", "-A")
				b.apply(t, wt, name, bin, token)
				gitIn(wt, nil, "add", "-A")
				hits := scanStaged(t, e, wt)
				if got := fpSet(f.kr, hits, map[string]string{"github": token}); !slices.Equal(got, []string{"github"}) {
					t.Errorf("%s: a repo's %s hid the staged token from the pre-commit scan", name, b.label)
				}
			})
		}
	}
}

// Every engine reports a line its author tagged as allowed, in every mode, pre-commit included:
// a blocked agent can add the comment itself, so only ignore.json may allow anything.
func TestNoEngineHonorsInlineAllowMarkers(t *testing.T) {
	f := getFixture(t)
	tags := map[string][]string{
		"betterleaks": {"betterleaks:allow", "gitleaks:allow"},
		"gitleaks":    {"gitleaks:allow", "betterleaks:allow"},
		"trufflehog":  {"trufflehog:ignore"},
		"titus":       {"pragma: allowlist secret", "titus:ignore"},
	}
	for _, name := range Names {
		for _, tag := range tags[name] {
			t.Run(name+"/"+strings.ReplaceAll(tag, " ", "_"), func(t *testing.T) {
				e := newEngine(t, name, f.kr)
				resetAudit()
				wt := worktree(t)
				sl := fake("slack")
				writeLines(t, wt, "a.txt", "line1", "line2", "SLACK="+sl+" # "+tag)
				gitIn(wt, nil, "add", "-A")
				want := []string{"slack"}
				if name == "betterleaks" || name == "gitleaks" {
					if got := fpSet(f.kr, scanStaged(t, e, wt), map[string]string{"slack": sl}); !slices.Equal(got, want) {
						t.Errorf("pre-commit scan honored %q (found %v)", tag, got)
					}
				}
				gitIn(wt, nil, "commit", "-q", "-m", "allowed")
				if got := fpSet(f.kr, scanGit(t, e, wt, core.Range{All: true}, stagedOpts(wt)), map[string]string{"slack": sl}); !slices.Equal(got, want) {
					t.Errorf("history scan honored %q (found %v)", tag, got)
				}
				var dirHits []core.Hit
				if err := e.ScanDir(context.Background(), wt, stagedOpts(wt), func(h core.Hit) { dirHits = append(dirHits, h) }); err != nil {
					t.Fatal(err)
				}
				assertSafe(t, name, dirHits)
				if got := fpSet(f.kr, dirHits, map[string]string{"slack": sl}); !slices.Equal(got, want) {
					t.Errorf("directory scan honored %q (found %v)", tag, got)
				}
			})
		}
	}
}

// ----- the index git hands a hook -----

const hookHelperEnv = "KG_HOOK_HELPER"

// hookHelper is what the pre-commit hook of TestPreCommitScanUnderRealGitCommits runs: the test
// binary itself, started by git with the environment git gives a hook, scanning the staged
// changes of the directory git started it in the way keyguard's hook does. It writes where it
// found something, never what.
func hookHelper() int {
	out, name := os.Getenv("KG_HOOK_RESULT"), os.Getenv(hookHelperEnv)
	f, err := os.OpenFile(out, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 2
	}
	defer f.Close()
	bin, err := testkit.LookupEngine(name)
	if err != nil {
		fmt.Fprintln(f, "ERR", err)
		return 0
	}
	e, err := New(name, bin, fp.NewEphemeral())
	if err != nil {
		fmt.Fprintln(f, "ERR", err)
		return 0
	}
	wd, _ := os.Getwd()
	env := map[string]string{}
	for _, k := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"} {
		env[k] = os.Getenv(k)
	}
	fmt.Fprintf(f, "ENV %v\n", env)
	err = e.ScanStaged(context.Background(), wd, core.ScanOpts{Loc: core.Location{Kind: "staged", Visibility: core.Local}}, func(h core.Hit) {
		fmt.Fprintf(f, "HIT %s:%d\n", h.Loc.Path, h.Loc.Line)
	})
	if err != nil {
		fmt.Fprintln(f, "ERR scan failed")
	}
	return 0
}

// git passes a hook GIT_INDEX_FILE as a path relative to the directory it starts the hook in,
// or the path of a temporary index (commit -a, commit --only). A scan that changes directory
// before it reads the index sees an empty one, finds nothing, and the commit goes through.
func TestPreCommitScanUnderRealGitCommits(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"betterleaks", "gitleaks"} {
		needEngine(t, name)
		t.Run(name, func(t *testing.T) {
			result := filepath.Join(t.TempDir(), "result")
			main := t.TempDir()
			gitIn(main, nil, "init", "-q", "-b", "main")
			writeLines(t, main, "tracked.txt", "one")
			writeLines(t, main, "sub/tracked2.txt", "two")
			writeLines(t, main, "other.txt", "three")
			gitIn(main, nil, "add", "-A")
			gitIn(main, nil, "commit", "-q", "-m", "base")
			hook := fmt.Sprintf("#!/bin/sh\nexec env %s=%s KG_HOOK_RESULT='%s' '%s'\n", hookHelperEnv, name, result, exe)
			hookPath := filepath.Join(main, ".git", "hooks", "pre-commit")
			if err := os.WriteFile(hookPath, []byte(hook), 0o755); err != nil {
				t.Fatal(err)
			}
			linked := filepath.Join(t.TempDir(), "wt")
			gitIn(main, nil, "worktree", "add", "-q", "-b", "side", linked)

			plants := map[string]string{}
			style := func(label, path string, in string, commit func()) {
				token := fake("github")
				plants[label] = path
				writeLines(t, in, path, "GITHUB_TOKEN="+token)
				commit()
			}
			style("plain", "plain.env", main, func() {
				gitIn(main, nil, "add", "plain.env")
				gitIn(main, nil, "commit", "-q", "-m", "plain")
			})
			style("commit -a", "tracked.txt", main, func() {
				gitIn(main, nil, "commit", "-q", "-a", "-m", "all")
			})
			style("commit --only", "other.txt", main, func() {
				gitIn(main, nil, "commit", "-q", "-m", "only", "--only", "other.txt")
			})
			style("subdirectory", "sub/tracked2.txt", main, func() {
				gitIn(filepath.Join(main, "sub"), nil, "commit", "-q", "-a", "-m", "sub")
			})
			style("linked worktree", "linked.env", linked, func() {
				gitIn(linked, nil, "add", "linked.env")
				gitIn(linked, nil, "commit", "-q", "-m", "linked")
			})

			b, err := os.ReadFile(result)
			if err != nil {
				t.Fatalf("the hook never ran: %v", err)
			}
			got := string(b)
			for label, path := range plants {
				if !strings.Contains(got, "HIT "+path+":1\n") {
					t.Errorf("%s: the staged token in %s was not found by the hook's scan", label, path)
				}
			}
			if strings.Contains(got, "ERR") {
				t.Errorf("the hook's scan reported an error:\n%s", strings.ReplaceAll(got, "\n", " | "))
			}
		})
	}
}
