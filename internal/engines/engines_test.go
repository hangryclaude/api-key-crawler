package engines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

func testOpts() core.ScanOpts {
	return core.ScanOpts{Loc: core.Location{Source: "github.com/x/y", Kind: "repo", Visibility: core.Private}}
}

func newEngine(t *testing.T, name string, kr core.Fingerprinter) core.Engine {
	t.Helper()
	e, err := New(name, needEngine(t, name), kr)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func scanGit(t *testing.T, e core.Engine, repo string, r core.Range, o core.ScanOpts) []core.Hit {
	t.Helper()
	var hits []core.Hit
	if err := e.ScanGit(context.Background(), repo, r, o, func(h core.Hit) { hits = append(hits, h) }); err != nil {
		t.Fatalf("%s ScanGit: %v", e.Name(), err)
	}
	assertSafe(t, e.Name(), hits)
	return hits
}

// assertSafe is the invariant every scan result must satisfy: no planted secret in the hits
// when marshaled, none in what the engine left in its scratch dir.
func assertSafe(t *testing.T, label string, hits []core.Hit) {
	t.Helper()
	b, err := json.Marshal(hits)
	if err != nil {
		t.Fatal(err)
	}
	assertNoRaw(t, label+" hits", b)
	assertScratchClean(t)
}

// expectedMiss lists, per engine, the planted secrets it does not report in full, and why.
// Everything else in the fixture must be found at its exact commit, path and line.
var expectedMiss = map[string]map[string]string{
	// np.mailgun.1 captures the hex after "key-", so its fingerprint is of that part only.
	"titus": {"mailgun": "partial capture: hex without the key- prefix"},
}

// genericOnly: gitleaks has no groq rule, but its generic rule still sees the line.
var genericOnly = map[string]map[string]bool{"gitleaks": {"groq": true}}

func TestScanGit(t *testing.T) {
	f := getFixture(t)
	idx := f.fpIndex()
	for _, name := range Names {
		for _, repo := range []string{f.work, f.mirror} {
			t.Run(name+"/"+filepath.Base(repo), func(t *testing.T) {
				e := newEngine(t, name, f.kr)
				resetAudit()
				before := snapshot(t, repo)
				hits := scanGit(t, e, repo, core.Range{All: true}, testOpts())
				if after := snapshot(t, repo); after != before {
					t.Errorf("scan modified the repository")
				}
				f.checkHits(t, name, hits, idx)
			})
		}
	}
}

// checkHits judges a full-history scan of the fixture.
func (f *fixture) checkHits(t *testing.T, engine string, hits []core.Hit, idx map[string]*plant) {
	t.Helper()
	found := map[string]bool{}
	for _, h := range hits {
		if h.Engine != engine {
			t.Errorf("hit engine %q, want %q", h.Engine, engine)
		}
		if h.Type != NormalizeType(engine, h.Rule) {
			t.Errorf("%s: type %q does not match the table for %q", engine, h.Type, h.Rule)
		}
		if h.Verified != core.Unverified {
			t.Errorf("%s %s: verified %q without verification", engine, h.Rule, h.Verified)
		}
		if h.Loc.Source != "github.com/x/y" || h.Loc.Kind != "repo" || h.Loc.Visibility != core.Private {
			t.Errorf("%s %s: template not copied: %+v", engine, h.Rule, h.Loc)
		}
		if h.Loc.Commit == "" || h.Loc.Path == "" || h.Loc.Line == 0 || h.Loc.Ref == "" || h.Loc.Author == "" || h.Loc.Date == "" {
			t.Errorf("%s %s: incomplete location %+v", engine, h.Rule, h.Loc)
		}
		wantURL := fmt.Sprintf("https://github.com/x/y/blob/%s/%s#L%d", h.Loc.Commit, h.Loc.Path, h.Loc.Line)
		if h.Loc.URL != wantURL {
			t.Errorf("%s %s: url %q, want %q", engine, h.Rule, h.Loc.URL, wantURL)
		}
		if h.Context == "" {
			t.Errorf("%s %s: empty context", engine, h.Rule)
		}
		p, ok := idx[h.FP]
		if !ok {
			f.allowUnplanted(t, engine, h)
			continue
		}
		found[p.name] = true
		// The location must be real: the value is on that line of that file at that commit.
		if line := f.lineAt(h.Loc.Commit, h.Loc.Path, h.Loc.Line); !strings.Contains(line, p.raw) {
			t.Errorf("%s %s: %s is not at %s:%s:%d", engine, h.Rule, p.name, short(h.Loc.Commit), h.Loc.Path, h.Loc.Line)
		}
		if h.Shape != fp.Shape(p.raw) || h.Len != len(p.raw) || h.Entropy != fp.Entropy(p.raw) {
			t.Errorf("%s %s: %s shape/len/entropy do not describe the value", engine, h.Rule, p.name)
		}
		if strings.Contains(h.Context, p.raw) || !strings.Contains(h.Context, "«"+fp.Shape(p.raw)+"»") {
			t.Errorf("%s %s: %s context is not the line with the value replaced by its shape (len %d, has value: %v)", engine, h.Rule, p.name, len(h.Context), strings.Contains(h.Context, p.raw))
		}
		if want := p.name; h.Type != want && !genericOnly[engine][p.name] {
			t.Errorf("%s %s: type %q, want %q", engine, h.Rule, h.Type, want)
		}
	}
	for _, p := range f.plants {
		if _, miss := expectedMiss[engine][p.name]; miss {
			continue
		}
		var at *core.Hit
		for i, h := range hits {
			if h.FP == f.kr.FP(p.raw) && h.Loc.Commit == p.commit && h.Loc.Path == p.path && h.Loc.Line == p.line {
				at = &hits[i]
				break
			}
		}
		if at == nil {
			t.Errorf("%s did not report %s at %s:%s:%d", engine, p.name, short(p.commit), p.path, p.line)
			continue
		}
		if at.Loc.Author != p.author || at.Loc.Date != p.date {
			t.Errorf("%s %s: author/date %q %q, want %q %q", engine, p.name, at.Loc.Author, at.Loc.Date, p.author, p.date)
		}
	}
	// Refs: a commit reachable only from a pull ref or a tag says so.
	for _, h := range hits {
		want := map[string]string{f.c["c4"]: "refs/heads/feature", f.c["c5"]: "refs/pull/1/head", f.c["c6"]: "refs/tags/v1"}[h.Loc.Commit]
		if want != "" && h.Loc.Ref != want {
			t.Errorf("%s %s: ref %q, want %q", engine, h.Rule, h.Loc.Ref, want)
		}
		if want == "" && h.Loc.Ref != "refs/heads/main" {
			t.Errorf("%s %s: ref %q, want refs/heads/main", engine, h.Rule, h.Loc.Ref)
		}
	}
	for name, why := range expectedMiss[engine] {
		p := f.byName(name)
		partial := f.kr.FP(strings.TrimPrefix(p.raw, "key-"))
		ok := false
		for _, h := range hits {
			ok = ok || h.FP == partial && h.Loc.Commit == p.commit && h.Loc.Path == p.path && h.Loc.Line == p.line
		}
		if !ok {
			t.Errorf("%s: documented behaviour for %s (%s) no longer holds", engine, name, why)
		}
	}
}

// allowUnplanted admits the two kinds of hit that are not a planted value: the documented
// partial capture, and a generic-rule hit sitting on a planted line (a fragment of the key).
func (f *fixture) allowUnplanted(t *testing.T, engine string, h core.Hit) {
	t.Helper()
	for name := range expectedMiss[engine] {
		p := f.byName(name)
		if h.FP == f.kr.FP(strings.TrimPrefix(p.raw, "key-")) {
			return
		}
	}
	if h.Type == Generic {
		for _, p := range f.plants {
			if h.Loc.Commit != "" && h.Loc.Path == p.path && strings.Contains(f.lineAt(h.Loc.Commit, h.Loc.Path, h.Loc.Line), p.raw) {
				return
			}
		}
	}
	t.Errorf("%s: unexpected hit %s (%s, %s) at %s:%s:%d", engine, h.Rule, h.Type, h.Shape, short(h.Loc.Commit), h.Loc.Path, h.Loc.Line)
}

func short(c string) string {
	if len(c) > 7 {
		return c[:7]
	}
	return c
}

// snapshot is the directory listing of a repo with sizes and mtimes: a read-only scan must
// leave it unchanged.
func snapshot(t *testing.T, dir string) string {
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
		rel, _ := filepath.Rel(dir, p)
		lines = append(lines, fmt.Sprintf("%s %d %d", rel, fi.Size(), fi.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func TestScanGitRevs(t *testing.T) {
	f := getFixture(t)
	idx := f.fpIndex()
	newOnly := map[string]bool{f.c["c3"]: true}
	for _, name := range Names {
		for _, repo := range []string{f.work, f.mirror} {
			t.Run(name+"/"+filepath.Base(repo), func(t *testing.T) {
				e := newEngine(t, name, f.kr)
				resetAudit()
				hits := scanGit(t, e, repo, core.Range{Revs: []string{f.c["c3"], "^" + f.c["c2"]}}, testOpts())
				for _, h := range hits {
					if !newOnly[h.Loc.Commit] {
						t.Errorf("%s: hit in %s, outside the range", name, short(h.Loc.Commit))
					}
				}
				for _, want := range []string{"stripe", "digitalocean"} {
					if !hasPlant(hits, f, idx, want) {
						t.Errorf("%s: %s from the new commit not reported", name, want)
					}
				}
				for _, old := range []string{"openai", "github", "mailgun", "slack", "npm", "sendgrid"} {
					if hasPlant(hits, f, idx, old) {
						t.Errorf("%s: %s from outside the range reported", name, old)
					}
				}
				// c3 moved the anthropic line; only blob-based titus sees the new blob.
				if name != "titus" && hasPlant(hits, f, idx, "anthropic") {
					t.Errorf("%s: unchanged anthropic line reported for c3", name)
				}

				// The sweep's shape: every ref, minus what the old tips already had.
				hits = scanGit(t, e, repo, core.Range{Revs: []string{"--all", "--not", f.c["c2"]}}, testOpts())
				got := plantNames(hits, f, idx)
				want := []string{"stripe", "digitalocean", "slack", "huggingface", "telegram", "npm", "sendgrid"}
				if name == "titus" {
					want = append(want, "anthropic") // the c3 version of app.py is a new blob
				}
				for _, w := range want {
					if !slices.Contains(got, w) {
						t.Errorf("%s --all --not c2: %s missing (got %v)", name, w, got)
					}
				}
				for _, g := range got {
					if !slices.Contains(want, g) {
						t.Errorf("%s --all --not c2: %s reported but was in the old history", name, g)
					}
				}
			})
		}
	}
}

func TestScanGitSince(t *testing.T) {
	f := getFixture(t)
	idx := f.fpIndex()
	// c3 is on main and under the tag; c4 is feature; c5 the pull ref; c6 the tag.
	afterC2 := []string{"stripe", "digitalocean", "slack", "huggingface", "telegram", "npm", "sendgrid"}
	afterC3 := []string{"slack", "huggingface", "telegram", "npm", "sendgrid"}
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			resetAudit()
			check := func(what string, r core.Range, want []string) {
				t.Helper()
				hits := scanGit(t, e, f.mirror, r, testOpts())
				got := sortedCopy(plantNames(hits, f, idx))
				want = sortedCopy(want)
				if !slices.Equal(got, want) {
					t.Errorf("%s: %s reported %v, want %v", name, what, got, want)
				}
			}
			// Every ref, but main only after c2. feature, the pull ref and the tag have no
			// recorded tip, so their commits come in full minus what c2 already covers.
			w := slices.Clone(afterC2)
			if name == "titus" {
				w = append(w, "anthropic") // c3 rewrote app.py: a new blob holding the old key
			}
			check("all since main@c2", core.Range{All: true, Since: map[string]string{"refs/heads/main": f.c["c2"]}}, w)

			// A recorded tip excludes everything it reaches, whichever ref it was recorded for.
			check("all since main@c2 feature@c3", core.Range{All: true, Since: map[string]string{"refs/heads/main": f.c["c2"], "refs/heads/feature": f.c["c3"]}}, afterC3)

			// Since alone scans only the refs it names.
			check("feature since c3", core.Range{Since: map[string]string{"refs/heads/feature": f.c["c3"]}}, []string{"huggingface", "slack", "telegram"})

			// A tip git has never heard of widens the scan instead of failing it.
			hits := scanGit(t, e, f.mirror, core.Range{All: true, Since: map[string]string{"refs/heads/main": strings.Repeat("ab", 20)}}, testOpts())
			if got := plantNames(hits, f, idx); len(got) < 12 {
				t.Errorf("%s: unknown since tip scanned only %v", name, got)
			}

			// Nothing new: no work, no error.
			check("main at its recorded tip", core.Range{Since: map[string]string{"refs/heads/main": f.c["c3"], "refs/heads/gone": f.c["c1"]}}, nil)
		})
	}
}

func sortedCopy(s []string) []string {
	s = slices.Clone(s)
	sort.Strings(s)
	return s
}

func plantNames(hits []core.Hit, f *fixture, idx map[string]*plant) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hits {
		if p, ok := idx[h.FP]; ok && !seen[p.name] {
			seen[p.name] = true
			out = append(out, p.name)
		}
	}
	return out
}

func hasPlant(hits []core.Hit, f *fixture, idx map[string]*plant, name string) bool {
	return slices.Contains(plantNames(hits, f, idx), name)
}

func TestBadInput(t *testing.T) {
	f := getFixture(t)
	for _, name := range Names {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, name, f.kr)
			ctx := context.Background()
			emit := func(core.Hit) { t.Error("hit from a failed scan") }
			cases := map[string]error{
				"empty range":  e.ScanGit(ctx, f.mirror, core.Range{}, testOpts(), emit),
				"output flag":  e.ScanGit(ctx, f.mirror, core.Range{Revs: []string{"--output=" + filepath.Join(t.TempDir(), "x")}}, testOpts(), emit),
				"space in rev": e.ScanGit(ctx, f.mirror, core.Range{Revs: []string{"main ^v1"}}, testOpts(), emit),
				"unknown rev":  e.ScanGit(ctx, f.mirror, core.Range{Revs: []string{"no-such-ref-anywhere"}}, testOpts(), emit),
				"not a repo":   e.ScanGit(ctx, t.TempDir(), core.Range{All: true}, testOpts(), emit),
				"missing path": e.ScanGit(ctx, "/nonexistent/repo", core.Range{All: true}, testOpts(), emit),
				"missing dir":  e.ScanDir(ctx, "/nonexistent/dir", testOpts(), emit),
			}
			for what, err := range cases {
				if err == nil {
					t.Errorf("%s: no error", what)
				}
			}
		})
	}
	t.Run("rules file", func(t *testing.T) {
		e := newEngine(t, "betterleaks", f.kr)
		o := testOpts()
		o.Rules = "/nonexistent/rules.toml"
		if err := e.ScanDir(context.Background(), t.TempDir(), o, func(core.Hit) {}); err == nil {
			t.Error("missing rules file accepted")
		}
	})
	t.Run("constructor", func(t *testing.T) {
		if _, err := New("nope", "/bin/true", f.kr); err == nil {
			t.Error("unknown engine accepted")
		}
		if _, err := New("titus", "/bin/true", nil); err == nil {
			t.Error("nil Fingerprinter accepted")
		}
	})
	t.Run("binary missing", func(t *testing.T) {
		e, err := New("betterleaks", filepath.Join(t.TempDir(), "betterleaks"), f.kr) // a directory that exists, a binary that does not
		if err != nil {
			t.Fatal(err)
		}
		if e.Available() || e.Version() != "" {
			t.Errorf("missing binary: available=%v version=%q", e.Available(), e.Version())
		}
		if err := e.ScanDir(context.Background(), t.TempDir(), testOpts(), func(core.Hit) {}); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Errorf("scan with no binary: %v", err)
		}
	})
}

func TestUnsupportedStaged(t *testing.T) {
	f := getFixture(t)
	for _, name := range []string{"trufflehog", "titus"} {
		e := newEngine(t, name, f.kr)
		if err := e.ScanStaged(context.Background(), f.work, testOpts(), func(core.Hit) {}); !errors.Is(err, core.ErrUnsupported) {
			t.Errorf("%s ScanStaged: %v, want ErrUnsupported", name, err)
		}
	}
}

func TestVersionAvailable(t *testing.T) {
	f := getFixture(t)
	for _, name := range Names {
		e := newEngine(t, name, f.kr)
		if !e.Available() || e.Name() != name {
			t.Errorf("%s: available=%v name=%q", name, e.Available(), e.Name())
		}
		// A different instrument: read the version straight off the binary.
		args := []string{"version"}
		if name == "trufflehog" {
			args = []string{"--no-update", "--version"}
		}
		out, _ := exec.Command(needEngine(t, name), args...).CombinedOutput()
		want := regexp.MustCompile(`\d+\.\d+\.\d+`).FindString(string(out))
		if want == "" || e.Version() != want {
			t.Errorf("%s version %q, binary says %q", name, e.Version(), want)
		}
	}
}

func TestCancel(t *testing.T) {
	f := getFixture(t)
	for _, name := range Names {
		e := newEngine(t, name, f.kr)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		err := e.ScanGit(ctx, f.mirror, core.Range{All: true}, testOpts(), func(core.Hit) {})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s: canceled scan returned %v", name, err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: cancel took %v", name, d)
		}
	}
}

// TestSourceNeverPrints: the engines package has no business writing to the terminal, which
// is where a raw value would escape in a log line.
func TestSourceNeverPrints(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"os.Stdout", "os.Stderr", "fmt.Print", "fmt.Fprint(os", "log.Print", "log.Fatal", "println("} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s uses %s", p, bad)
			}
		}
	}
}
