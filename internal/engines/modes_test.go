package engines

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"keyguard/internal/core"
)

// worktree makes a throwaway repo with one clean commit.
func worktree(t *testing.T) string {
	t.Helper()
	wt := t.TempDir()
	gitIn(wt, nil, "init", "-q", "-b", "main")
	writeLines(t, wt, "a.txt", "line1", "line2")
	gitIn(wt, nil, "add", "-A")
	gitIn(wt, nil, "commit", "-q", "-m", "base")
	return wt
}

func writeLines(t *testing.T, root, rel string, lines ...string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func stagedOpts(wt string) core.ScanOpts {
	return core.ScanOpts{Loc: core.Location{Source: "local:" + wt, Kind: "staged", Visibility: core.Local}}
}

func scanStaged(t *testing.T, e core.Engine, wt string) []core.Hit {
	t.Helper()
	var hits []core.Hit
	if err := e.ScanStaged(context.Background(), wt, stagedOpts(wt), func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatalf("%s ScanStaged: %v", e.Name(), err)
	}
	assertSafe(t, e.Name(), hits)
	return hits
}

func fpSet(kr interface{ FP(string) string }, hits []core.Hit, plants map[string]string) (found []string) {
	for name, raw := range plants {
		for _, h := range hits {
			if h.FP == kr.FP(raw) {
				found = append(found, name)
				break
			}
		}
	}
	slices.Sort(found)
	return found
}

func TestScanStaged(t *testing.T) {
	f := getFixture(t)
	for _, name := range []string{"betterleaks", "gitleaks"} {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			wt := worktree(t)
			gh, st, np := fake("github"), fake("stripe"), fake("npm")
			writeLines(t, wt, "a.txt", "line1", "line2", "TOKEN="+gh)
			writeLines(t, wt, "b/new.env", "STRIPE="+st)
			gitIn(wt, nil, "add", "-A")
			// Changed after staging: the working file has it, the index does not.
			writeLines(t, wt, "a.txt", "line1", "line2", "TOKEN="+gh, "NPM="+np)

			hits := scanStaged(t, e, wt)
			if got := fpSet(f.kr, hits, map[string]string{"github": gh, "stripe": st, "npm": np}); !slices.Equal(got, []string{"github", "stripe"}) {
				t.Fatalf("staged scan found %v, want github and stripe only", got)
			}
			for _, h := range hits {
				if h.Loc.Commit != "" || h.Loc.Source != "local:"+wt || h.Loc.Kind != "staged" || h.Loc.Visibility != core.Local || h.Loc.URL != "" {
					t.Errorf("%s: location %+v", h.Rule, h.Loc)
				}
				want := map[string]int{"a.txt": 3, "b/new.env": 1}[h.Loc.Path]
				if h.Loc.Line != want || want == 0 {
					t.Errorf("%s: line %d at %s, want %d", h.Rule, h.Loc.Line, h.Loc.Path, want)
				}
				// The index, not the working file, is what was scanned.
				if staged := gitIn(wt, nil, "show", ":"+h.Loc.Path); strings.Contains(staged, np) {
					t.Errorf("%s: index of %s holds the unstaged value", h.Rule, h.Loc.Path)
				}
				if !strings.Contains(h.Context, "«") || strings.Contains(h.Context, gh) || strings.Contains(h.Context, st) {
					t.Errorf("%s: context does not hold a shape placeholder, or holds a value (len %d)", h.Rule, len(h.Context))
				}
			}

			// An empty index is a no-op, not an error.
			gitIn(wt, nil, "reset", "-q")
			if hits := scanStaged(t, e, wt); len(hits) != 0 {
				t.Errorf("nothing staged but %d hits", len(hits))
			}
		})
	}
}

func TestScanStagedFirstCommit(t *testing.T) {
	f := getFixture(t)
	for _, name := range []string{"betterleaks", "gitleaks"} {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			wt := t.TempDir()
			gitIn(wt, nil, "init", "-q", "-b", "main") // no commits yet
			st := fake("stripe")
			writeLines(t, wt, "x.env", "S="+st)
			gitIn(wt, nil, "add", "-A")
			hits := scanStaged(t, e, wt)
			if got := fpSet(f.kr, hits, map[string]string{"stripe": st}); !slices.Equal(got, []string{"stripe"}) {
				t.Errorf("first-commit staged scan found %v", got)
			}
		})
	}
}

// A pre-commit hook for `git commit -a` runs with GIT_INDEX_FILE pointing at a temporary
// index; the scan has to read that one, and a scan of a mirror must not be redirected by the
// GIT_DIR the same hook sets.
func TestHookEnvironment(t *testing.T) {
	f := getFixture(t)
	for _, name := range []string{"betterleaks", "gitleaks"} {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			wt := worktree(t)
			gh := fake("github")
			writeLines(t, wt, "a.txt", "line1", "line2", "TOKEN="+gh) // modified, not staged in the real index
			tmpIdx := filepath.Join(t.TempDir(), "index")
			idxEnv := []string{"GIT_INDEX_FILE=" + tmpIdx}
			gitIn(wt, idxEnv, "read-tree", "HEAD")
			gitIn(wt, idxEnv, "add", "a.txt")

			t.Setenv("GIT_INDEX_FILE", tmpIdx)
			t.Setenv("GIT_DIR", filepath.Join(wt, ".git"))
			hits := scanStaged(t, e, wt)
			if got := fpSet(f.kr, hits, map[string]string{"github": gh}); !slices.Equal(got, []string{"github"}) {
				t.Errorf("staged scan under the hook's temporary index found %v", got)
			}

			// Same environment, scanning a different repo: GIT_DIR must not win.
			hits = scanGit(t, newEngine(t, name, f.kr), f.mirror, core.Range{All: true}, testOpts())
			if len(hits) < 12 {
				t.Errorf("scan of the mirror under a hook GIT_DIR found %d hits", len(hits))
			}
			known := map[string]bool{}
			for _, c := range f.c {
				known[c] = true
			}
			for _, h := range hits {
				if !known[h.Loc.Commit] {
					t.Errorf("hit in commit %s, which is not in the mirror", short(h.Loc.Commit))
				}
			}
		})
	}
}

// Inline allow comments are covered by TestNoEngineHonorsInlineAllowMarkers (blind_test.go): no
// engine honors one in any mode.

// A repo must not be able to switch off its own scan: .gitleaks.toml with an allowlist of
// ".*" silenced betterleaks and gitleaks completely when the config was left to discovery.
func TestRepoConfigCannotSilenceScan(t *testing.T) {
	f := getFixture(t)
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			wt := worktree(t)
			gh := fake("github")
			writeLines(t, wt, ".gitleaks.toml", "[extend]", "useDefault = true", "[allowlist]", `regexes = [".*"]`)
			writeLines(t, wt, ".betterleaks.toml", "[extend]", "useDefault = true", "[allowlist]", `regexes = [".*"]`)
			writeLines(t, wt, "a.txt", "line1", "line2", "TOKEN="+gh)
			gitIn(wt, nil, "add", "-A")
			if name == "betterleaks" || name == "gitleaks" {
				if hits := scanStaged(t, e, wt); len(fpSet(f.kr, hits, map[string]string{"github": gh})) != 1 {
					t.Errorf("repo config silenced the staged scan")
				}
			}
			gitIn(wt, nil, "commit", "-q", "-m", "c")
			if hits := scanGit(t, e, wt, core.Range{All: true}, stagedOpts(wt)); len(fpSet(f.kr, hits, map[string]string{"github": gh})) != 1 {
				t.Errorf("repo config silenced the history scan")
			}
			var dirHits []core.Hit
			if err := e.ScanDir(context.Background(), wt, stagedOpts(wt), func(h core.Hit) { dirHits = append(dirHits, h) }); err != nil {
				t.Fatal(err)
			}
			if len(fpSet(f.kr, dirHits, map[string]string{"github": gh})) != 1 {
				t.Errorf("repo config silenced the directory scan")
			}
		})
	}
}

// dirTree lays out a directory the way ~/dev looks to `keyguard learn`.
func dirTree(t *testing.T) (root string, plants map[string]string) {
	t.Helper()
	root = t.TempDir()
	plants = map[string]string{
		"github": fake("github"), "linear": fake("linear"), "groq": fake("groq"), "npm": fake("npm"), "stripe": fake("stripe"),
	}
	writeLines(t, root, ".env", "A=1", "GITHUB_TOKEN="+plants["github"])
	writeLines(t, root, "deep/er/file.yaml", "a: b", "linear: "+plants["linear"])
	writeLines(t, root, ".hidden/conf.txt", "GROQ_API_KEY="+plants["groq"])
	writeLines(t, root, "dist/app.min.js", `var k="`+plants["npm"]+`";`)
	// Version-control metadata is not part of a directory scan, for any engine.
	writeLines(t, root, ".git/config", "[remote \"origin\"]", "\turl = https://x:"+plants["stripe"]+"@github.com/o/r.git")
	// Neither is the scanned directory's own opinion of what to ignore.
	writeLines(t, root, ".gitleaks.toml", "[extend]", "useDefault = true", "[allowlist]", `regexes = [".*"]`)
	return root, plants
}

func TestScanDir(t *testing.T) {
	f := getFixture(t)
	want := map[string][]string{
		"betterleaks": {"github", "groq", "linear", "npm"},
		"gitleaks":    {"github", "groq", "linear", "npm"},
		"trufflehog":  {"github", "groq", "linear", "npm"},
		"titus":       {"github", "groq", "linear", "npm"},
	}
	wantPath := map[string]string{"github": ".env", "linear": "deep/er/file.yaml", "groq": ".hidden/conf.txt", "npm": "dist/app.min.js"}
	wantLine := map[string]int{"github": 2, "linear": 2, "groq": 1, "npm": 1}
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			root, plants := dirTree(t)
			o := core.ScanOpts{Loc: core.Location{Source: "local:" + root, Kind: "file", Visibility: core.Local}}
			var hits []core.Hit
			if err := e.ScanDir(context.Background(), root, o, func(h core.Hit) { hits = append(hits, h) }); err != nil {
				t.Fatal(err)
			}
			assertSafe(t, name, hits)
			if got := fpSet(f.kr, hits, plants); !slices.Equal(got, want[name]) {
				t.Errorf("found %v, want %v", got, want[name])
			}
			for _, h := range hits {
				for pname, raw := range plants {
					if h.FP != f.kr.FP(raw) {
						continue
					}
					if h.Loc.Path != wantPath[pname] || h.Loc.Line != wantLine[pname] || h.Loc.Commit != "" || h.Loc.Kind != "file" || h.Loc.Source != "local:"+root {
						t.Errorf("%s: location %+v, want %s:%d", pname, h.Loc, wantPath[pname], wantLine[pname])
					}
					if strings.Contains(h.Context, raw) || h.Context == "" {
						t.Errorf("%s: context empty or holds the value (len %d)", pname, len(h.Context))
					}
				}
			}

			// One file is a valid target too.
			hits = hits[:0]
			if err := e.ScanDir(context.Background(), filepath.Join(root, ".env"), o, func(h core.Hit) { hits = append(hits, h) }); err != nil {
				t.Fatal(err)
			}
			assertSafe(t, name, hits)
			if got := fpSet(f.kr, hits, plants); !slices.Equal(got, []string{"github"}) {
				t.Errorf("single file scan found %v", got)
			}
			for _, h := range hits {
				if h.Loc.Path != ".env" {
					t.Errorf("single file path %q", h.Loc.Path)
				}
			}
		})
	}
}

// The shipped rules file extends the defaults, so passing it must change nothing yet: the
// same planted values come out with and without it, with a relative path too.
func TestShippedRulesFile(t *testing.T) {
	f := getFixture(t)
	for _, name := range []string{"betterleaks", "gitleaks"} {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			root, plants := dirTree(t)
			run := func(rules string) []string {
				o := core.ScanOpts{Rules: rules, Loc: core.Location{Source: "local:" + root, Kind: "file", Visibility: core.Local}}
				var hits []core.Hit
				if err := e.ScanDir(context.Background(), root, o, func(h core.Hit) { hits = append(hits, h) }); err != nil {
					t.Fatalf("rules %q: %v", rules, err)
				}
				assertSafe(t, name, hits)
				return fpSet(f.kr, hits, plants)
			}
			with, without := run("../../rules/keyguard.toml"), run("")
			if len(without) < 3 || !slices.Equal(with, without) {
				t.Errorf("with the rules file %v, without %v", with, without)
			}
		})
	}
}
