package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelftestListOnlyAndPartialRuns(t *testing.T) {
	m := newMachine(t)
	if r := m.kg("selftest", "--list"); r.code != 0 || !strings.Contains(r.out, "reftx-noverify") || !strings.Contains(r.out, "quiet-stash") || !strings.Contains(r.out, "--only takes") {
		t.Errorf("--list: %d\n%s", r.code, r.out)
	}
	// One check on its own: it runs, it passes, and it is not written down as a full selftest.
	r := m.kg("selftest", "--only", "reftx-noverify", "--no-latency")
	if r.code != 0 || !strings.Contains(r.out, "stops --no-verify from committing a learned key") || !strings.Contains(r.out, "partial run") {
		t.Errorf("--only reftx-noverify: %d\n%s", r.code, r.out)
	}
	if strings.Contains(r.out, "the layers around the gates") {
		t.Error("--only a gate check ran the layers too")
	}
	if _, err := os.Stat(filepath.Join(m.root, "state", "selftest.json")); err == nil {
		t.Error("a partial run was recorded: the doctor would read it as a full selftest")
	}
	// A misspelt name is an error that names the right one, not a quiet pass.
	if r := m.kg("selftest", "--only", "reftx-noverfy"); r.code != exitFailed || !strings.Contains(r.out, `did you mean "reftx-noverify"`) {
		t.Errorf("a misspelt --only: %d\n%s", r.code, r.out)
	}
	if r := m.kg("selftest", "--runs", "0"); r.code != exitUsage {
		t.Errorf("--runs 0: %d", r.code)
	}
}

// A broken gate has to fail the command, on the screen and in the exit code, and say how to
// look at it again; a selftest that cannot fail is decoration.
func TestSelftestExitsOneWhenAGateIsBroken(t *testing.T) {
	w := newWorld(t)
	// The real binary with its reference-transaction hook switched off.
	exe := filepath.Join(t.TempDir(), "keyguard")
	script := "#!/bin/sh\nif [ \"$1\" = hook ] && [ \"$2\" = reference-transaction ]; then cat >/dev/null; exit 0; fi\nexec '" + binPath + "' \"$@\"\n"
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	w.seams.exe = exe

	out, errs, code := w.cli("selftest", "--only", "reftx-noverify", "--no-latency")
	if code != exitFound {
		t.Fatalf("a broken ref gate: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitFound, out, errs)
	}
	for _, want := range []string{"FAIL", "stops --no-verify from committing a learned key", "was not blocked", "1 of 2 checks FAILED: reftx-noverify",
		"keyguard selftest --only reftx-noverify", "A gate or a layer failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("the screen lacks %q:\n%s", want, out)
		}
	}

	out, _, code = w.cli("selftest", "--only", "reftx-noverify", "--no-latency", "--json")
	var rec struct {
		OK    bool `json:"ok"`
		Gates struct {
			OK     bool `json:"ok"`
			Checks []struct {
				ID string
				OK bool
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatalf("selftest --json: %v\n%s", err, out)
	}
	failed := []string{}
	for _, c := range rec.Gates.Checks {
		if !c.OK {
			failed = append(failed, c.ID)
		}
	}
	if code != exitFound || rec.OK || rec.Gates.OK || strings.Join(failed, ",") != "reftx-noverify" {
		t.Errorf("--json: exit %d ok=%v gates ok=%v failed=%v", code, rec.OK, rec.Gates.OK, failed)
	}
	// And nothing was recorded for the doctor: a partial run is not a selftest.
	if _, err := os.Stat(filepath.Join(w.paths.State, "selftest.json")); err == nil {
		t.Error("a partial, failed run was recorded as the selftest")
	}
}

// dirState lists every file under dir with its size and time, so a change shows as a difference.
func dirState(t *testing.T, dir string) string {
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

// A scan can read mirrors that belong to somebody else, as they are: config.json's "mirrors"
// says where they are, and --no-fetch promises nothing in them moves, not even when the
// upstream has moved on and a fetch would have changed them.
func TestScanNoFetchReadsTheMirrorsAsTheyAre(t *testing.T) {
	m := newMachine(t)
	token := fakeKey(t, "ghp_", 36)

	origin := m.repo("origin")
	m.write("origin/README.md", "a public project\n")
	m.write("origin/settings.py", "API_TOKEN = \""+token+"\"\n")
	m.mustGit(origin, "add", "-A")
	m.mustGit(origin, "commit", "-q", "-m", "first")

	mirrors := filepath.Join(m.dir, "somebody-elses-cache", "mirrors")
	mirror := filepath.Join(mirrors, "github.com", "o", "n.git")
	if err := os.MkdirAll(filepath.Dir(mirror), 0o700); err != nil {
		t.Fatal(err)
	}
	m.mustGit(m.dir, "clone", "-q", "--mirror", origin, mirror)

	cfg, _ := json.Marshal(map[string]any{"mirrors": mirrors})
	m.write(filepath.Join(m.root, "state", "config.json"), string(cfg))
	snap := `{"version": 1, "updated": "2026-11-03T12:00:00Z", "sources": [{"id": "github.com/o/n", "kind": "repo", "owner": "o", "name": "n", ` +
		`"account": "o", "clone_url": "https://github.com/o/n.git", "visibility": "public", "pushed_at": "2026-11-03T11:00:00Z"}]}`
	m.write(filepath.Join(m.root, "state", "inventory.json"), snap)

	// The upstream moves on: a fetch would now change the mirror.
	m.write("origin/more.txt", "more\n")
	m.mustGit(origin, "add", "-A")
	m.mustGit(origin, "commit", "-q", "-m", "second")
	tips := func() string {
		return m.mustGit(m.dir, "--git-dir="+mirror, "for-each-ref", "--format=%(objectname) %(refname)")
	}
	tipsBefore, filesBefore := tips(), dirState(t, mirrors)

	r := m.kg("scan", "--full", "--repo", "github.com/o/n", "--no-fetch", "--no-verify", "--engines", "betterleaks")
	if r.code != 0 {
		t.Fatalf("scan --no-fetch: exit %d\n%s", r.code, r.out)
	}
	if !strings.Contains(r.out, "betterleaks") || strings.Contains(r.out, "open findings: none") || !strings.Contains(r.out, "open findings: ") {
		t.Errorf("the scan of the mirror should have found the token:\n%s", r.out)
	}
	if strings.Contains(r.out, token) {
		t.Error("the scan printed the token")
	}
	if tips() != tipsBefore || dirState(t, mirrors) != filesBefore {
		t.Errorf("--no-fetch changed the mirror:\n%s\n%s", tipsBefore, tips())
	}

	// The control: the same scan with fetching on does move the mirror, so the check above
	// is about the flag and not about a mirror that could not have changed.
	if r := m.kg("scan", "--full", "--repo", "github.com/o/n", "--no-verify", "--engines", "betterleaks"); r.code != 0 {
		t.Fatalf("scan with fetching: exit %d\n%s", r.code, r.out)
	}
	if tips() == tipsBefore {
		t.Error("a scan with fetching on left the mirror where it was; the control proves nothing")
	}

	// The findings kept the shape, never the value.
	err := filepath.WalkDir(m.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if b, rerr := os.ReadFile(p); rerr == nil && strings.Contains(string(b), token) {
			t.Errorf("%s holds the token", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// A mirror that is not there is said, not cloned, and the config's root must exist.
func TestScanNoFetchRefusesToCloneAndToMakeTheRoot(t *testing.T) {
	m := newMachine(t)
	mirrors := filepath.Join(m.dir, "empty-cache", "mirrors")
	if err := os.MkdirAll(mirrors, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(map[string]any{"mirrors": mirrors})
	m.write(filepath.Join(m.root, "state", "config.json"), string(cfg))
	m.write(filepath.Join(m.root, "state", "inventory.json"), `{"version": 1, "updated": "2026-11-03T12:00:00Z", "sources": [{"id": "github.com/o/n", "kind": "repo", `+
		`"owner": "o", "name": "n", "account": "o", "clone_url": "https://github.com/o/n.git", "visibility": "public", "pushed_at": "2026-11-03T11:00:00Z"}]}`)
	before := dirState(t, mirrors)
	r := m.kg("scan", "--full", "--repo", "github.com/o/n", "--no-fetch", "--no-verify", "--engines", "betterleaks")
	if !strings.Contains(r.out, "fetching is off") {
		t.Errorf("a source with no mirror should be said, with the reason:\n%s", r.out)
	}
	if dirState(t, mirrors) != before {
		t.Error("--no-fetch made something under the mirrors root")
	}

	absent := filepath.Join(m.dir, "absent", "mirrors")
	cfg, _ = json.Marshal(map[string]any{"mirrors": absent})
	m.write(filepath.Join(m.root, "state", "config.json"), string(cfg))
	if r := m.kg("scan", "--full", "--repo", "github.com/o/n", "--no-fetch"); r.code == exitOK {
		t.Errorf("a mirrors root that is not there was accepted: %s", r.out)
	}
	if _, err := os.Stat(absent); err == nil {
		t.Error("--no-fetch made the mirrors root")
	}
}
