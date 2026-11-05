package bench

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/core"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// repoNamed finds a name that falls in the wanted half; the split is frozen, so it always will.
func repoNamed(prefix, half string) string {
	for i := 0; ; i++ {
		if n := prefix + string(rune('a'+i%26)) + string(rune('a'+i/26)); Half(n) == half {
			return n
		}
	}
}

func TestLoadNaturalMeasuresAndSplitsTheRepos(t *testing.T) {
	root := t.TempDir()
	tuneName, heldName := repoNamed("tune-", HalfTune), repoNamed("held-", HalfHeldOut)
	writeTree(t, root, map[string]string{
		tuneName + "/a.go":        "package a\n\nfunc A() {}\n", // 3 lines, 23 bytes
		tuneName + "/sub/b.txt":   "one\ntwo\n",                 // 2 lines, 8 bytes
		tuneName + "/.git/config": "[core]\n\tfoo = 1\n",        // never counted
		heldName + "/main.rs":     "fn main() {}\n",             // 1 line, 13 bytes
		".hidden/x.txt":           "x\n",                        // not a repo
		"loose-file.txt":          "not a repo\n",               // not a directory
	})
	linked := t.TempDir() // a directory elsewhere, linked in: counts as a repo
	writeTree(t, linked, map[string]string{"z.py": "print(1)\n"})
	if err := os.Symlink(linked, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}

	repos, err := LoadNatural(root)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]NaturalRepo{}
	for _, r := range repos {
		by[r.Name] = r
	}
	if len(repos) != 3 {
		t.Fatalf("%d repos: %+v", len(repos), repos)
	}
	if r := by[tuneName]; r.Files != 2 || r.Bytes != 23+8 || r.Lines != 5 || r.Half != HalfTune {
		t.Errorf("%s: %+v", tuneName, r)
	}
	if r := by[heldName]; r.Files != 1 || r.Bytes != 13 || r.Lines != 1 || r.Half != HalfHeldOut {
		t.Errorf("%s: %+v", heldName, r)
	}
	if r := by["linked"]; r.Files != 1 || r.Bytes != 9 || r.Dir == filepath.Join(root, "linked") || r.Half != Half("linked") {
		t.Errorf("linked: %+v", r)
	}
}

// Corpus C is never in git: a tree under a repository is refused before anything is read.
func TestLoadNaturalRefusesAGitWorkTree(t *testing.T) {
	repo := t.TempDir()
	if out, err := exec.Command("git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	root := filepath.Join(repo, "cache", "bench")
	writeTree(t, root, map[string]string{"r/a.txt": "a\n"})
	if _, err := LoadNatural(root); err == nil || !strings.Contains(err.Error(), "git work tree") {
		t.Errorf("a corpus inside a repository was accepted: %v", err)
	}
}

// dirEngine reports canned hits per directory name.
type dirEngine struct {
	fakeEngine
	byDir map[string][]core.Hit
	mu    sync.Mutex
	seen  []string
}

func (d *dirEngine) ScanDir(_ context.Context, dir string, o core.ScanOpts, emit core.Emit) error {
	d.mu.Lock()
	d.seen = append(d.seen, filepath.Base(dir))
	d.mu.Unlock()
	for _, h := range d.byDir[filepath.Base(dir)] {
		h.Loc = o.Loc
		h.Loc.Path = filepath.Join(dir, "f.txt")
		emit(h)
	}
	return nil
}

func TestScoreNaturalCountsNoisePerMBAndPerLine(t *testing.T) {
	root := t.TempDir()
	tuneName, heldName := repoNamed("tune-", HalfTune), repoNamed("held-", HalfHeldOut)
	// 600,000 bytes and 5,000 lines in the tune repo; 400,000 bytes and 4,000 lines in the held-out one
	writeTree(t, root, map[string]string{
		tuneName + "/a.txt": strings.Repeat(strings.Repeat("x", 119)+"\n", 5000),
		heldName + "/b.txt": strings.Repeat(strings.Repeat("y", 99)+"\n", 4000),
	})
	repos, err := LoadNatural(root)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(fpv, rule, typ string) core.Hit {
		return core.Hit{Engine: "e", FP: fpv, Rule: rule, Type: typ, Len: 30, Shape: "x…"}
	}
	e := &dirEngine{fakeEngine: fakeEngine{name: "e", avail: true}, byDir: map[string][]core.Hit{
		tuneName: {mk("f1", "generic-api-key", "generic"), mk("f2", "generic-api-key", "generic"), mk("f3", "jwt", "jwt")},
		heldName: {mk("f2", "generic-api-key", "generic"), mk("f4", "private-key", "private-key")}, // f2 again: one distinct report
	}}
	noArch := &fakeEngine{name: "dirless", avail: true} // ScanDir is unsupported
	gone := &fakeEngine{name: "gone", avail: false}
	// triage drops f3 and f4
	keep := func(h core.Hit) bool { return h.FP != "f3" && h.FP != "f4" }

	res, err := ScoreNatural(context.Background(), []core.Engine{e, noArch, gone}, repos, NaturalOptions{Keep: keep, Recall: 0.98})
	if err != nil {
		t.Fatal(err)
	}
	if !within(res.MB, 1.0, 1e-9) || res.Lines != 9000 {
		t.Fatalf("%.3f MB, %d lines", res.MB, res.Lines)
	}
	ne := res.Engines[0]
	// four distinct reports (f1..f4) in 1.0 MB; two survive triage
	if ne.Reported != 4 || ne.Alerts != 2 || !within(ne.FPPerMB, 4, 1e-9) || !within(ne.AlertsPerMB, 2, 1e-9) || !within(ne.AlertsPerMLine, 2.0/9000*1e6, 1e-6) {
		t.Errorf("engine: %+v", ne)
	}
	// a fingerprint belongs to the half of the first repo it was seen in, and the repos are visited in
	// name order: f2 and f4 come from the held-out repo, f1 and f3 from the tune one
	if h := ne.ByHalf[HalfTune]; h.Reported != 2 || h.Alerts != 1 || !within(h.PerMB, 1/0.6, 1e-9) {
		t.Errorf("tune half: %+v", h)
	}
	if h := ne.ByHalf[HalfHeldOut]; h.Reported != 2 || h.Alerts != 1 || !within(h.PerMB, 1/0.4, 1e-9) {
		t.Errorf("held-out half: %+v", h)
	}
	for _, prev := range Prevalences {
		want := PrecisionAt(prev, 0.98, 2.0/9000)
		if got := ne.PrecisionAt[prevalenceLabel(prev)]; !within(got, want, 1e-12) {
			t.Errorf("precision at %g: %v, want %v", prev, got, want)
		}
	}
	if ne.ByRule["generic-api-key"] != 2 || ne.ByRule["jwt"] != 0 {
		t.Errorf("alerts by rule: %v", ne.ByRule)
	}
	if res.Engines[1].Skipped != "no directory mode" || res.Engines[2].Skipped == "" {
		t.Errorf("engines without a directory mode or a binary: %+v %+v", res.Engines[1], res.Engines[2])
	}
	if res.Pipeline.Alerts != 2 || res.Pipeline.Reported != 2 {
		t.Errorf("pipeline: %+v", res.Pipeline)
	}

	out := t.TempDir()
	if err := res.WriteTo(out); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(filepath.Join(out, "natural.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"no secret planted", "alerts per MB", "precision at 1e-3", "skipped: no directory mode", "waiting for a verdict"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("natural.md lacks %q", want)
		}
	}
}

// The pipeline's precision on natural code comes from a judged stratified sample, with a Wilson
// interval, or the rule of three when the sample held no false alert.
func TestScoreNaturalEstimatesPipelinePrecisionFromAJudgedSample(t *testing.T) {
	root := t.TempDir()
	name := repoNamed("r-", HalfTune)
	writeTree(t, root, map[string]string{name + "/a.txt": "hello\n"})
	repos, err := LoadNatural(root)
	if err != nil {
		t.Fatal(err)
	}
	var hits []core.Hit
	for i := 0; i < 60; i++ {
		hits = append(hits, core.Hit{Engine: "e", FP: "fp-" + string(rune('A'+i%26)) + string(rune('a'+i/26)), Rule: "r", Type: map[bool]string{true: "alpha", false: "beta"}[i%3 != 0], Shape: "x…", Len: 20})
	}
	e := &dirEngine{fakeEngine: fakeEngine{name: "e", avail: true}, byDir: map[string][]core.Hit{name: hits}}
	keep := func(core.Hit) bool { return true }

	// every sampled alert judged real: nothing false in the sample, so the rule of three speaks
	res, err := ScoreNatural(context.Background(), []core.Engine{e}, repos, NaturalOptions{Keep: keep, SamplePer: 10, Seed: 4, Judge: func(core.Hit) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	p := res.Precision
	if p == nil || !p.ZeroFP || p.Precision != 1 || p.Sampled != 20 || !within(p.Lo, 1-3.0/20, 1e-12) || len(res.Sample) != 20 {
		t.Fatalf("zero-FP estimate: %+v (%d sampled)", p, len(res.Sample))
	}
	// two thirds judged real
	res, err = ScoreNatural(context.Background(), []core.Engine{e}, repos, NaturalOptions{Keep: keep, SamplePer: 10, Seed: 4, Judge: func(h core.Hit) bool { return h.Type == "alpha" }})
	if err != nil {
		t.Fatal(err)
	}
	p = res.Precision
	// strata: alpha 40 alerts (10 sampled, all real), beta 20 (10 sampled, none real): weighted 40/60
	if p == nil || p.ZeroFP || p.Census || !within(p.Precision, 40.0/60, 1e-12) || p.Lo >= p.Precision || p.Hi <= p.Precision {
		t.Errorf("estimate: %+v", p)
	}
	for _, s := range res.Sample {
		if s.ID == "" || s.Rule == "" || s.Repo != name || s.Shape == "" {
			t.Errorf("sampled alert lacks display fields: %+v", s)
		}
	}
	// the same seed draws the same sample
	again, _ := ScoreNatural(context.Background(), []core.Engine{e}, repos, NaturalOptions{Keep: keep, SamplePer: 10, Seed: 4, Judge: func(h core.Hit) bool { return h.Type == "alpha" }})
	for i := range res.Sample {
		if res.Sample[i] != again.Sample[i] {
			t.Fatal("the same seed drew a different sample")
		}
	}
}

// With a real engine: clean filler code is quiet, and one obvious fake in a repo is reported once.
func TestScoreNaturalWithARealEngine(t *testing.T) {
	root := t.TempDir()
	fl := &filler{r: newRand(31, "natural")}
	clean, dirty := repoNamed("clean-", HalfTune), repoNamed("dirty-", HalfHeldOut)
	for _, n := range []string{clean, dirty} {
		for i := 0; i < 40; i++ {
			ext := fl.randomExt()
			writeTree(t, root, map[string]string{filepath.Join(n, fl.path(ext)): fl.file(ext, 200)})
		}
	}
	g := &Gen{r: newRand(31, "natural-plant")}
	planted := g.token(4.0, lit("ghp_"), rnd(alnum, 36))
	writeTree(t, root, map[string]string{dirty + "/deploy.env": "GITHUB_TOKEN=" + planted + "\n"})
	repos, err := LoadNatural(root)
	if err != nil {
		t.Fatal(err)
	}
	c := sharedCorpus(t)
	engines := realEngines(t, c, "betterleaks")
	res, err := ScoreNatural(context.Background(), engines, repos, NaturalOptions{Recall: 0.98, Keep: func(core.Hit) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	ne := res.Engines[0]
	if ne.Error != "" || ne.Skipped != "" {
		t.Fatalf("betterleaks: %+v", ne)
	}
	if ne.Reported != 1 || ne.ByHalf[HalfHeldOut].Reported != 1 || ne.ByHalf[HalfTune].Reported != 0 {
		t.Errorf("betterleaks on %.1f MB of filler and one fake: %+v", res.MB, ne)
	}
	t.Logf("betterleaks scanned %.1f MB, %d lines, in %.2f s: %d report (the planted fake), %.3f per MB", res.MB, res.Lines, ne.Seconds, ne.Reported, ne.FPPerMB)
	b, _ := os.ReadFile(filepath.Join(root, dirty, "deploy.env"))
	out := t.TempDir()
	if err := res.WriteTo(out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"natural.json", "natural.md"} {
		got, _ := os.ReadFile(filepath.Join(out, name))
		if strings.Contains(string(got), planted) || len(b) == 0 {
			t.Errorf("%s carries the planted value", name)
		}
	}
}
