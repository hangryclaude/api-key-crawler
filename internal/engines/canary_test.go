package engines

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
)

// stderrSpy runs a real engine behind a script in the test's temp dir that copies what the
// engine writes to stderr into a log, and still passes it on. The binary is only executed.
func stderrSpy(t *testing.T, name, real, logf string, kr core.Fingerprinter) core.Engine {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	script := fmt.Sprintf("#!/bin/sh\n'%s' \"$@\" 2>'%s.part'\nrc=$?\ncat '%s.part' >> '%s'\ncat '%s.part' >&2\nrm -f '%s.part'\nexit $rc\n", real, logf, logf, logf, logf, logf)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	e, err := New(name, bin, kr)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// The canary (STEAL P0-04): plant secrets, run every engine in every mode, then look for them
// in every byte the engines wrote where we can see it: the engine's own stderr (the real one,
// before our filter), its scratch directory (audited just before it is removed, by
// assertScratchClean), the keyguard data root, and the errors and hits that came back.
func TestNoEngineWritesOrPrintsARawValue(t *testing.T) {
	f := getFixture(t)
	dir, _ := dirTree(t)
	key := realKeys(t)["rsa"]
	writeLines(t, dir, "id_rsa", strings.Split(key, "\n")...)
	writeLines(t, dir, "db.env", "DATABASE_URL="+uriOf("postgres", "appuser", register(tok(alnumCS, 18)), "db.example.invalid:5432/app"))
	repo := worktree(t)
	staged := fake("github")
	writeLines(t, repo, "staged.env", "GITHUB_TOKEN="+staged)
	gitIn(repo, nil, "add", "-A")

	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			logf := filepath.Join(t.TempDir(), "stderr.log")
			e := stderrSpy(t, name, needEngine(t, name), logf, f.kr)
			resetAudit()
			ctx := context.Background()
			var hits []core.Hit
			emit := func(h core.Hit) { hits = append(hits, h) }
			errs := []error{
				e.ScanDir(ctx, dir, testOpts(), emit),
				e.ScanGit(ctx, f.mirror, core.Range{All: true}, testOpts(), emit),
				e.ScanGit(ctx, f.mirror, core.Range{Revs: []string{f.c["c3"], "^" + f.c["c2"]}}, testOpts(), emit),
				// Failures speak too: a repository that is not one, a range that does not exist.
				e.ScanGit(ctx, t.TempDir(), core.Range{All: true}, testOpts(), emit),
				e.ScanGit(ctx, f.mirror, core.Range{Revs: []string{"no-such-ref-anywhere"}}, testOpts(), emit),
			}
			if name == "betterleaks" || name == "gitleaks" {
				errs = append(errs, e.ScanStaged(ctx, repo, testOpts(), emit))
			}
			for i, err := range errs {
				if err != nil {
					assertNoRaw(t, fmt.Sprintf("error %d", i), []byte(err.Error()))
				}
			}
			assertSafe(t, name, hits)
			if len(hits) == 0 {
				t.Fatal("the engine found nothing: the canary proves nothing")
			}
			b, _ := os.ReadFile(logf)
			assertNoRaw(t, name+"'s own stderr", b)
		})
	}

	// Nothing is left under the data root, and nothing there ever held a value.
	home := os.Getenv("KEYGUARD_HOME")
	filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		assertNoRaw(t, "keyguard data root file "+strings.TrimPrefix(p, home), b)
		return nil
	})
}
