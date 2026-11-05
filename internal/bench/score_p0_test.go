package bench

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"keyguard/internal/core"
)

// p0Truth is a truth file small enough to check the P0-24 arithmetic by hand: lengths, halves
// and a line shared by two plants.
func p0Truth(t *testing.T) (dir string, f func(string) string) {
	t.Helper()
	dir = t.TempDir()
	kr := KeyringFor(5)
	f = func(s string) string { return kr.FP("value-" + s) }
	pl := func(id, typ, path string, line, length int, half string) Plant {
		return Plant{ID: id, Type: typ, Variant: "env", Positive: true, Detectable: true, FP: f(id), Len: length, Half: half,
			Location: Location{Ref: "refs/heads/main", Commit: strings.Repeat("a", 40), Path: path, Line: line}}
	}
	pem := pl("pem", "pk", "k.pem", 10, 1600, HalfTune)
	pem.Location.EndLine = 12
	neg := func(id, kind, path string, line int, half string) Plant {
		return Plant{ID: id, Type: "alpha", Variant: "negative", Kind: kind, FP: f(id), Half: half,
			Location: Location{Ref: "refs/heads/main", Commit: strings.Repeat("a", 40), Path: path, Line: line}}
	}
	tr := &Truth{Schema: truthSchema, Seed: 5, Scale: 1, Repo: "repo", Stats: Stats{Lines: 100006, Positives: 6}, Plants: []Plant{
		pl("a1", "alpha", "a.env", 2, 40, HalfTune),
		pl("a2", "alpha", "b.py", 4, 30, HalfHeldOut),
		pl("b1", "beta", "c.py", 7, 20, HalfTune),
		pl("m1", "alpha", "minified.js", 1, 40, HalfTune),
		pl("m2", "alpha", "minified.js", 1, 40, HalfTune),
		pem,
		neg("n1", "twin-shape", "d.env", 3, HalfTune),
		neg("n2", "placeholder", "README.md", 3, HalfHeldOut),
	}}
	if err := tr.save(dir); err != nil {
		t.Fatal(err)
	}
	return dir, f
}

func lenHit(engine, typ, fpv, path string, line, n int) core.Hit {
	return core.Hit{Engine: engine, Rule: "r", Type: typ, FP: fpv, Len: n, Shape: "x…", Loc: core.Location{Path: path, Line: line}}
}

// STEAL P0-24: a hit is a true positive when its span covers min(len, 12) characters of the
// secret, whatever fingerprint or rule it has; the type is scored apart.
func TestScoreCreditsASpanThatCoversThePlant(t *testing.T) {
	dir, f := p0Truth(t)
	e1 := &fakeEngine{name: "e1", avail: true, hits: []core.Hit{
		lenHit("e1", "alpha", f("a1"), "a.env", 2, 40),    // its fingerprint
		lenHit("e1", "generic", "x2", "b.py", 4, 30),      // another fingerprint, same line, the plant's length
		lenHit("e1", "alpha", "x3", "c.py", 7, 8),         // too short: 8 < min(20, 12)
		lenHit("e1", "alpha", "x4", "minified.js", 1, 40), // a line with two plants: scored by fingerprint only
		lenHit("e1", "generic", "x5", "k.pem", 11, 64),    // the middle line of a multi-line key
		lenHit("e1", "alpha", f("n1"), "d.env", 3, 40),    // an invalid twin
		lenHit("e1", "alpha", f("n2"), "a.env", 2, 40),    // a lookalike's fingerprint on a plant's line stays a lookalike
		lenHit("e1", "alpha", "x8", "b.py", 4, 230),       // far longer than the plant: a whole line, not the secret
		lenHit("e1", "alpha", "x9", "z.py", 1, 40),        // noise
	}}
	res, err := ScoreWith(context.Background(), []core.Engine{e1}, nil, dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	e := res.Engines[0]
	eq := func(name string, got, want int) {
		t.Helper()
		if got != want {
			t.Errorf("%s: got %d, want %d", name, got, want)
		}
	}
	eq("reported", e.Reported, 9)
	eq("tp", e.TP, 3)
	eq("tp by containment", e.TPContained, 2)
	eq("fp negative", e.FPNegative, 2)
	eq("fp extent", e.FPExtent, 3)
	eq("fp other", e.FPOther, 1)
	eq("found", e.Found, 3)
	eq("found detectable", e.FoundDetectable, 3)
	// the type is scored apart: the generic hits found their plants and were mistyped
	eq("type total", e.TypeTotal, 3)
	eq("type ok", e.TypeOK, 1)
	if !near(e.TypeAccuracy, 1.0/3) || !near(e.Precision, 3.0/9) {
		t.Errorf("type accuracy %.4f precision %.4f", e.TypeAccuracy, e.Precision)
	}
	classes := map[string]int{}
	for _, fpos := range e.FalsePositives {
		classes[fpos.Class]++
	}
	if classes["negative:twin-shape"] != 1 || classes["negative:placeholder"] != 1 || classes["extent"] != 3 || classes["other"] != 1 {
		t.Errorf("false-positive classes %v", classes)
	}
	// the type scores follow the plant for true positives
	if ts := e.ByType["alpha"]; ts.Found != 2 || ts.TP != 2 {
		t.Errorf("alpha: %+v", *ts)
	}
	if ts := e.ByType["pk"]; ts.Found != 1 || ts.TP != 1 {
		t.Errorf("pk: %+v", *ts)
	}
}

func TestScoreHalvesAndTheOverfitGap(t *testing.T) {
	dir, f := p0Truth(t)
	e1 := &fakeEngine{name: "e1", avail: true, hits: []core.Hit{
		lenHit("e1", "alpha", f("a1"), "a.env", 2, 40),    // tune, found
		lenHit("e1", "generic", "x2", "b.py", 4, 30),      // held-out, found by span
		lenHit("e1", "alpha", "x3", "c.py", 7, 8),         // tune, extent
		lenHit("e1", "alpha", "x4", "minified.js", 1, 40), // tune, extent
		lenHit("e1", "generic", "x5", "k.pem", 11, 64),    // tune, found by span
		lenHit("e1", "alpha", f("n1"), "d.env", 3, 40),    // tune lookalike
		lenHit("e1", "alpha", f("n2"), "a.env", 2, 40),    // held-out lookalike
		lenHit("e1", "alpha", "x8", "b.py", 4, 230),       // held-out extent
		lenHit("e1", "alpha", "x9", "z.py", 1, 40),        // noise: belongs to no half
	}}
	res, err := ScoreWith(context.Background(), []core.Engine{e1}, nil, dir, ScoreOptions{OutDir: t.TempDir(), Keep: func(core.Hit) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	e := res.Engines[0]
	tu, ho := e.ByHalf[HalfTune], e.ByHalf[HalfHeldOut]
	if tu.Positives != 5 || tu.Detectable != 5 || tu.Found != 2 || !near(tu.Recall, 0.4) || tu.Reported != 5 || tu.TP != 2 || !near(tu.Precision, 0.4) {
		t.Errorf("tune: %+v", *tu)
	}
	if ho.Positives != 1 || ho.Found != 1 || !near(ho.Recall, 1) || ho.Reported != 3 || ho.TP != 1 || !near(ho.Precision, 1.0/3) {
		t.Errorf("held-out: %+v", *ho)
	}
	if lo, hi := Wilson(1, 1); !near(ho.RecallLo, lo) || !near(ho.RecallHi, hi) {
		t.Errorf("held-out interval %.4f %.4f", ho.RecallLo, ho.RecallHi)
	}
	// the noise hit belongs to neither half, so the halves hold 8 of the 9 reports
	if tu.Reported+ho.Reported != e.Reported-1 {
		t.Errorf("halves hold %d reports of %d", tu.Reported+ho.Reported, e.Reported)
	}
	// the pipeline keeps everything here, so the gap is the engine's
	o := res.Overfit
	if o == nil || !near(o.RecallTune, 0.4) || !near(o.RecallHeldOut, 1) || !near(o.RecallGap, -0.6) || !near(o.PrecisionGap, 0.4-1.0/3) {
		t.Errorf("overfit: %+v", o)
	}
	// the human-readable report counts held-out misses and never lists them
	e2 := &fakeEngine{name: "e2", avail: true, hits: []core.Hit{lenHit("e2", "alpha", f("a1"), "a.env", 2, 40)}}
	res, err = ScoreWith(context.Background(), []core.Engine{e2}, nil, dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	md := res.Markdown()
	miss := md[strings.Index(md, "## Misses"):]
	miss = miss[:strings.Index(miss, "\n## ")]
	if strings.Contains(miss, "a2") {
		t.Errorf("a held-out miss is listed in the report:\n%s", miss)
	}
	if !strings.Contains(miss, "b1") || !strings.Contains(miss, "held-out half, not listed") {
		t.Errorf("tune misses should be listed and held-out ones counted:\n%s", miss)
	}
}

func TestScoreMarginalPrecision(t *testing.T) {
	dir, f := p0Truth(t)
	e1 := &fakeEngine{name: "e1", avail: true, hits: []core.Hit{
		lenHit("e1", "alpha", f("a1"), "a.env", 2, 40),
		lenHit("e1", "generic", "x2", "b.py", 4, 30),
		lenHit("e1", "alpha", "x3", "c.py", 7, 8),
		lenHit("e1", "alpha", "x4", "minified.js", 1, 40),
		lenHit("e1", "generic", "x5", "k.pem", 11, 64),
		lenHit("e1", "alpha", f("n1"), "d.env", 3, 40),
		lenHit("e1", "alpha", f("n2"), "a.env", 2, 40),
		lenHit("e1", "alpha", "x8", "b.py", 4, 230),
		lenHit("e1", "alpha", "x9", "z.py", 1, 40),
	}}
	e2 := &fakeEngine{name: "e2", avail: true, hits: []core.Hit{
		lenHit("e2", "alpha", f("a1"), "a.env", 2, 40), // the one report both made
		lenHit("e2", "alpha", "y1", "q.py", 3, 40),     // only e2
	}}
	e3 := &fakeEngine{name: "e3", avail: false}
	res, err := ScoreWith(context.Background(), []core.Engine{e1, e2, e3}, nil, dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	m1, m2 := res.Engines[0].Marginal, res.Engines[1].Marginal
	// e1: 9 reports, one shared with e2; its true positives are a1 (shared), x2 and x5
	if m1 == nil || m1.Reported != 8 || m1.TP != 2 || !near(m1.Precision, 0.25) || m1.Found != 2 {
		t.Errorf("e1 marginal: %+v", m1)
	}
	if m2 == nil || m2.Reported != 1 || m2.TP != 0 || m2.Precision != 0 || m2.Found != 0 {
		t.Errorf("e2 marginal: %+v", m2)
	}
	if res.Engines[2].Marginal != nil {
		t.Error("an engine that did not run has a marginal contribution")
	}
	// standalone precision is the engine alone; the report shows both
	if !near(res.Engines[0].Precision, 3.0/9) || !near(res.Engines[1].Precision, 0.5) {
		t.Errorf("standalone precision %.4f and %.4f", res.Engines[0].Precision, res.Engines[1].Precision)
	}
	md := res.Markdown()
	for _, want := range []string{"## Standalone, marginal and pipeline precision", "| e1 | 33.3% | 8 | 2 | 25.0% | 2 |", "## The two halves", "## Does the corpus prove the target?"} {
		if !strings.Contains(md, want) {
			t.Errorf("results.md lacks %q", want)
		}
	}
}

// Precision where secrets are rare follows from the false alerts per line and the recall.
func TestScorePrecisionAtLowPrevalence(t *testing.T) {
	dir, f := p0Truth(t)
	e1 := &fakeEngine{name: "e1", avail: true, hits: []core.Hit{
		lenHit("e1", "alpha", f("a1"), "a.env", 2, 40),
		lenHit("e1", "alpha", f("n1"), "d.env", 3, 40),
		lenHit("e1", "alpha", "x9", "z.py", 1, 40),
	}}
	res, err := ScoreWith(context.Background(), []core.Engine{e1}, nil, dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	e := res.Engines[0]
	// 100,006 lines, 6 of them plants: 100,000 clean lines; two false alerts
	if !within(e.FPPerMLine, 20, 1e-9) {
		t.Errorf("false alerts per million lines = %v, want 20", e.FPPerMLine)
	}
	for _, prev := range Prevalences {
		want := PrecisionAt(prev, e.Recall, 2e-5)
		if got := e.PrecisionAt[prevalenceLabel(prev)]; !within(got, want, 1e-12) {
			t.Errorf("precision at %g = %v, want %v", prev, got, want)
		}
	}
	if !(e.PrecisionAt["1e-3"] > e.PrecisionAt["1e-5"] && e.PrecisionAt["1e-5"] > e.PrecisionAt["1e-6"]) {
		t.Errorf("precision should fall with the prevalence: %v", e.PrecisionAt)
	}
	if !strings.Contains(res.Markdown(), "## Precision where secrets are rare") {
		t.Error("the report lacks the prevalence table")
	}
}

// verifyEngine answers differently with verification on, and records how it was asked.
type verifyEngine struct {
	fakeEngine
	mu            sync.Mutex
	calls         []bool
	raw, verified []core.Hit
}

func (v *verifyEngine) ScanGit(_ context.Context, _ string, _ core.Range, o core.ScanOpts, emit core.Emit) error {
	v.mu.Lock()
	v.calls = append(v.calls, o.Verify)
	v.mu.Unlock()
	hs := v.raw
	if o.Verify {
		hs = v.verified
	}
	for _, h := range hs {
		emit(h)
	}
	return nil
}

func TestScoreRawPrecisionHasVerificationOffAndThePipelineMayHaveItOn(t *testing.T) {
	dir, f := p0Truth(t)
	live := lenHit("e", "alpha", f("a1"), "a.env", 2, 40)
	live.Verified = core.Live
	v := &verifyEngine{fakeEngine: fakeEngine{name: "e", avail: true},
		raw:      []core.Hit{lenHit("e", "alpha", f("a1"), "a.env", 2, 40), lenHit("e", "alpha", "x9", "z.py", 1, 40)},
		verified: []core.Hit{live}}
	keepLive := func(h core.Hit) bool { return h.Verified == core.Live }

	res, err := ScoreWith(context.Background(), []core.Engine{v}, nil, dir, ScoreOptions{OutDir: t.TempDir(), Keep: keepLive})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.calls) != 1 || v.calls[0] || res.PipelineVerified || res.Pipeline.TP != 0 {
		t.Errorf("without Verify: calls %v, verified %v, pipeline TP %d", v.calls, res.PipelineVerified, res.Pipeline.TP)
	}

	v.calls = nil
	res, err = ScoreWith(context.Background(), []core.Engine{v}, nil, dir, ScoreOptions{OutDir: t.TempDir(), Keep: keepLive, Verify: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.calls) != 2 || v.calls[0] || !v.calls[1] {
		t.Errorf("with Verify the engine should run raw and then verified: %v", v.calls)
	}
	if !res.PipelineVerified || res.Pipeline.TP != 1 || res.Pipeline.Reported != 1 || !near(res.Pipeline.Precision, 1) {
		t.Errorf("pipeline from the verified run: %+v", res.Pipeline)
	}
	// the engine row and the union stay raw
	if e := res.Engines[0]; e.Reported != 2 || e.TP != 1 || !near(e.Precision, 0.5) || res.Union.Reported != 2 {
		t.Errorf("engine row: reported %d tp %d", e.Reported, e.TP)
	}
	if !strings.Contains(res.Markdown(), "verification on") {
		t.Error("the report does not say the pipeline was verified")
	}
}

func TestScoreMeasuresSpeedWhenAsked(t *testing.T) {
	dir, f := p0Truth(t)
	n := 0
	e := &countEngine{fakeEngine: fakeEngine{name: "e", avail: true, hits: []core.Hit{lenHit("e", "alpha", f("a1"), "a.env", 2, 40)}}, n: &n}
	res, err := ScoreWith(context.Background(), []core.Engine{e}, nil, dir, ScoreOptions{OutDir: t.TempDir(), SpeedRuns: 4})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1+4 {
		t.Errorf("the engine ran %d times, want one scored run and four timed", n)
	}
	if len(res.Speed) != 1 || res.Speed[0].Runs != 4 || res.Speed[0].Engine != "e" || res.Speed[0].Repo != "repo" {
		t.Fatalf("speed: %+v", res.Speed)
	}
	if !strings.Contains(res.Markdown(), "## Speed") {
		t.Error("the report lacks the speed table")
	}
	res, err = ScoreWith(context.Background(), []core.Engine{e}, nil, dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil || len(res.Speed) != 0 {
		t.Errorf("speed measured without being asked: %v %v", res.Speed, err)
	}
}

type countEngine struct {
	fakeEngine
	n *int
}

func (c *countEngine) ScanGit(ctx context.Context, repo string, r core.Range, o core.ScanOpts, emit core.Emit) error {
	*c.n++
	return c.fakeEngine.ScanGit(ctx, repo, r, o, emit)
}

// The planted corpus reports whether it proves the target, and the real engines' intervals follow from the plant counts.
func TestScoreReportsTheGateAndTheIntervals(t *testing.T) {
	c := sharedCorpus(t)
	res, err := ScoreWith(context.Background(), realEngines(t, c, "betterleaks"), nil, c.Dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Gate.Sufficient || res.Gate.Detectable != c.Truth.Stats.Detectable {
		t.Errorf("gate: %+v", res.Gate)
	}
	e := res.Engines[0]
	lo, hi := Wilson(e.FoundDetectable, e.Detectable)
	if !near(e.RecallLo, lo) || !near(e.RecallHi, hi) || e.RecallLo >= e.Recall || e.RecallHi < e.Recall {
		t.Errorf("recall %.4f interval %.4f to %.4f", e.Recall, e.RecallLo, e.RecallHi)
	}
	for ty, ts := range e.ByType {
		if ts.Detectable > 0 && (ts.DetectableLo > ts.DetectableRecall || ts.DetectableHi < ts.DetectableRecall) {
			t.Errorf("type %s: recall %.3f outside its interval %.3f to %.3f", ty, ts.DetectableRecall, ts.DetectableLo, ts.DetectableHi)
		}
	}
	// the corpus is enriched; the precision it implies at one secret in a million lines is far below its own
	if e.PrecisionAt["1e-6"] >= e.Precision || e.FPPerMLine <= 0 {
		t.Errorf("precision %.3f, at 1e-6 %.4f, %.0f false alerts per Mline", e.Precision, e.PrecisionAt["1e-6"], e.FPPerMLine)
	}
	if res.Corpus.Lines < 100000 {
		t.Errorf("%d lines", res.Corpus.Lines)
	}
	checkNoRaw(t, c, filepath.Join(c.Dir, "truth.json"))
	md := res.Markdown()
	for _, want := range []string{"## Does the corpus prove the target?", "Detectable recall by type, with the 95% Wilson interval", "## Twins", "98% proved"} {
		if !strings.Contains(md, want) {
			t.Errorf("results.md lacks %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join(c.Dir, "truth.json")); err != nil {
		t.Fatal(err)
	}
}

// The known matcher names the key it holds, not a provider, so its true positives say nothing
// about whether a type was right and are left out of the type score.
func TestTheKnownMatchersTypeIsNotScored(t *testing.T) {
	dir, f := p0Truth(t)
	k := &fakeEngine{name: "k", avail: true, hits: []core.Hit{
		{Engine: "known", Type: "known", FP: f("a1"), Len: 40, Shape: "x…", Loc: core.Location{Path: "a.env", Line: 2}},
		lenHit("k", "alpha", f("b1"), "c.py", 7, 20),
	}}
	res, err := ScoreWith(context.Background(), []core.Engine{k}, nil, dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	e := res.Engines[0]
	if e.TP != 2 || e.TypeTotal != 1 || e.TypeOK != 0 {
		t.Errorf("tp %d, type total %d, type ok %d: the known hit must not be typed", e.TP, e.TypeTotal, e.TypeOK)
	}
	if got := typeAcc(EngineResult{}); got != "·" {
		t.Errorf("a row with no typed hit shows %q", got)
	}
}
