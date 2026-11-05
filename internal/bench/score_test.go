package bench

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// fakeEngine replays canned hits; the scorer only needs the Engine contract.
type fakeEngine struct {
	name  string
	hits  []core.Hit
	err   error
	avail bool
}

func (f *fakeEngine) Name() string    { return f.name }
func (f *fakeEngine) Version() string { return "test" }
func (f *fakeEngine) Available() bool { return f.avail }
func (f *fakeEngine) ScanGit(_ context.Context, _ string, r core.Range, _ core.ScanOpts, emit core.Emit) error {
	if !r.All {
		return fmt.Errorf("the scorer must scan every ref")
	}
	for _, h := range f.hits {
		emit(h)
	}
	return f.err
}
func (f *fakeEngine) ScanStaged(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}
func (f *fakeEngine) ScanDir(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// handTruth is a truth file small enough to check the scorer's arithmetic by hand.
func handTruth(t *testing.T) (dir string, kr *fp.Keyring) {
	t.Helper()
	dir = t.TempDir()
	kr = KeyringFor(5)
	f := func(s string) string { return kr.FP("value-" + s) }
	tr := &Truth{Schema: truthSchema, Seed: 5, Scale: 1, Repo: "repo", Plants: []Plant{
		{ID: "p1", Type: "alpha", Variant: "env", Positive: true, Detectable: true, FP: f("p1"), AltFPs: []string{f("p1-alt")}, Location: Location{Path: "a.env", Line: 2}},
		{ID: "p2", Type: "alpha", Variant: "py", Positive: true, Detectable: true, FP: f("p2"), Location: Location{Path: "b.py", Line: 4}},
		{ID: "p3", Type: "beta", Variant: "py", Positive: true, Detectable: true, FP: f("p3"), Location: Location{Path: "c.py", Line: 7}},
		{ID: "p4", Type: "beta", Variant: "zip", Positive: true, Detectable: false, FP: f("p4"), Location: Location{Path: "d.zip", Line: 1}},
		{ID: "p5", Type: "gamma", Variant: "env", Positive: true, Detectable: true, FP: f("p5"), Location: Location{Path: "e.env", Line: 1}},
		{ID: "n1", Type: "alpha", Variant: "negative", Kind: "placeholder", FP: f("n1"), Location: Location{Path: "README.md", Line: 3}},
		{ID: "n2", Type: "reference", Variant: "negative", Kind: "code-ref", Location: Location{Path: "src/x.py", Line: 1}},
	}}
	for i := range tr.Plants {
		tr.Plants[i].Location.Ref = "refs/heads/main"
		tr.Plants[i].Location.Commit = strings.Repeat("a", 40)
	}
	if err := tr.save(dir); err != nil {
		t.Fatal(err)
	}
	return dir, kr
}

func hit(engine, fpv, path string, line int) core.Hit {
	return core.Hit{Engine: engine, Rule: "r-" + engine, Type: "alpha", FP: fpv, Shape: "x…", Loc: core.Location{Path: path, Line: line}}
}

func TestScoreMath(t *testing.T) {
	dir, kr := handTruth(t)
	f := func(s string) string { return kr.FP("value-" + s) }
	e1 := &fakeEngine{name: "e1", avail: true, hits: []core.Hit{
		hit("e1", f("p1-alt"), "a.env", 2),   // found through an alternate extent
		hit("e1", f("p2"), "b.py", 4),        // found
		hit("e1", f("p2"), "b.py", 4),        // the same fingerprint again: one reported secret
		hit("e1", f("p4"), "d.zip!x", 1),     // found, though not detectable by design
		hit("e1", f("n1"), "README.md", 3),   // a lookalike, by fingerprint
		hit("e1", "unknown1", "src/x.py", 9), // a lookalike, by file (the code reference has no value)
		hit("e1", "unknown2", "c.py", 7),     // p3's line, wrong extent
		hit("e1", "unknown3", "z.py", 1),     // noise
	}}
	e2 := &fakeEngine{name: "e2", avail: true, hits: []core.Hit{
		hit("e2", f("p3"), "c.py", 7),
		hit("e2", f("p5"), "e.env", 1),
	}}
	e3 := &fakeEngine{name: "e3", avail: false}

	// the pipeline's triage drops one lookalike and the noise
	keep := func(h core.Hit) bool { return h.FP != f("n1") && h.FP != "unknown3" }
	res, err := ScoreWith(context.Background(), []core.Engine{e1, e2, e3}, nil, dir, ScoreOptions{Keep: keep, OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	a := res.Engines[0]
	want := func(name string, got, want int) {
		t.Helper()
		if got != want {
			t.Errorf("%s: got %d, want %d", name, got, want)
		}
	}
	want("e1 hits", a.Hits, 8)
	want("e1 reported", a.Reported, 7) // the duplicate p2 hit folds away
	want("e1 tp", a.TP, 3)
	want("e1 fp negative", a.FPNegative, 2)
	want("e1 fp extent", a.FPExtent, 1)
	want("e1 fp other", a.FPOther, 1)
	want("e1 positives", a.Positives, 5)
	want("e1 detectable", a.Detectable, 4)
	want("e1 found", a.Found, 3)
	want("e1 found detectable", a.FoundDetectable, 2)
	if !near(a.Recall, 0.5) || !near(a.RecallAll, 0.6) || !near(a.Precision, 3.0/7) {
		t.Errorf("e1 recall %.4f recall(all) %.4f precision %.4f", a.Recall, a.RecallAll, a.Precision)
	}
	if got := strings.Join(a.Missed, ","); got != "p3,p5" {
		t.Errorf("e1 missed detectable = %s", got)
	}
	if got := strings.Join(a.NearMiss, ","); got != "p3" {
		t.Errorf("e1 near-miss = %s", got)
	}
	// alpha reported: p1, p2 (true), the placeholder n1 and the noise hit typed alpha by the engine
	if ts := a.ByType["alpha"]; ts.Total != 2 || ts.Found != 2 || !near(ts.Recall, 1) || ts.Reported != 4 || ts.TP != 2 || !near(ts.Precision, 0.5) {
		t.Errorf("e1 alpha: %+v", *ts)
	}
	// beta reported: p4 (true) and the extent hit on p3's line, which belongs to p3's type
	if ts := a.ByType["beta"]; ts.Total != 2 || ts.Found != 1 || ts.Detectable != 1 || ts.FoundDetectable != 0 || ts.Reported != 2 || ts.TP != 1 {
		t.Errorf("e1 beta: %+v", *ts)
	}
	if ts := a.ByType["reference"]; ts.Reported != 1 || ts.TP != 0 {
		t.Errorf("e1 reference: %+v", *ts)
	}
	if v := a.ByVariant["py"]; v.Total != 2 || v.Found != 1 {
		t.Errorf("e1 py variant: %+v", *v)
	}
	if v := a.ByVariant["zip"]; v.Total != 1 || v.Found != 1 || v.Detectable != 0 {
		t.Errorf("e1 zip variant: %+v", *v)
	}
	if a.Skipped != "" || a.Error != "" {
		t.Errorf("e1 skipped=%q error=%q", a.Skipped, a.Error)
	}
	classes := map[string]int{}
	for _, fpos := range a.FalsePositives {
		classes[fpos.Class]++
	}
	if classes["negative:placeholder"] != 1 || classes["negative:code-ref"] != 1 || classes["extent"] != 1 || classes["other"] != 1 || len(a.FalsePositives) != 4 {
		t.Errorf("e1 false-positive classes: %v", classes)
	}

	b := res.Engines[1]
	want("e2 tp", b.TP, 2)
	want("e2 found detectable", b.FoundDetectable, 2)
	if !near(b.Precision, 1) || !near(b.Recall, 0.5) {
		t.Errorf("e2 recall %.4f precision %.4f", b.Recall, b.Precision)
	}
	if c := res.Engines[2]; c.Skipped == "" || c.Hits != 0 {
		t.Errorf("the unavailable engine ran: %+v", c)
	}

	u := res.Union
	want("union reported", u.Reported, 9)
	want("union tp", u.TP, 5)
	want("union found detectable", u.FoundDetectable, 4)
	if !near(u.Recall, 1) || !near(u.RecallAll, 1) || !near(u.Precision, 5.0/9) {
		t.Errorf("union recall %.4f all %.4f precision %.4f", u.Recall, u.RecallAll, u.Precision)
	}
	if len(u.Missed) != 0 {
		t.Errorf("union missed %v", u.Missed)
	}

	p := res.Pipeline
	want("pipeline reported", p.Reported, 7) // n1 and the noise are triaged away
	want("pipeline tp", p.TP, 5)
	want("pipeline fp negative", p.FPNegative, 1)
	want("pipeline fp extent", p.FPExtent, 1)
	want("pipeline fp other", p.FPOther, 0)
	if !near(p.Precision, 5.0/7) || !near(p.Recall, 1) {
		t.Errorf("pipeline precision %.4f recall %.4f", p.Precision, p.Recall)
	}
}

func TestScoreWritesBothReports(t *testing.T) {
	dir, kr := handTruth(t)
	e := &fakeEngine{name: "e1", avail: true, hits: []core.Hit{hit("e1", kr.FP("value-p1"), "a.env", 2)}}
	if _, err := Score(context.Background(), []core.Engine{e}, nil, dir); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(filepath.Join(dir, "results.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"## Engines", "## Recall by type", "## Precision by type", "## Recall by variant", "## Misses", "## False positives", "| e1 |", "| union |", "| pipeline |"} {
		if !strings.Contains(string(md), h) {
			t.Errorf("results.md lacks %q", h)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "results.json")); err != nil {
		t.Error(err)
	}
}

func TestScoreReportsAnEngineError(t *testing.T) {
	dir, kr := handTruth(t)
	e := &fakeEngine{name: "bad", avail: true, err: fmt.Errorf("boom"), hits: []core.Hit{hit("bad", kr.FP("value-p2"), "b.py", 4)}}
	res, err := ScoreWith(context.Background(), []core.Engine{e}, nil, dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Engines[0].Error != "boom" || res.Engines[0].TP != 1 {
		t.Errorf("an engine error must be recorded and its partial hits kept: %+v", res.Engines[0])
	}
}

type hangingEngine struct{ fakeEngine }

func (h *hangingEngine) ScanGit(ctx context.Context, _ string, _ core.Range, _ core.ScanOpts, _ core.Emit) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestScoreBoundsAHungEngine(t *testing.T) {
	dir, kr := handTruth(t)
	hung := &hangingEngine{fakeEngine{name: "hung", avail: true}}
	ok := &fakeEngine{name: "ok", avail: true, hits: []core.Hit{hit("ok", kr.FP("value-p2"), "b.py", 4)}}
	res, err := ScoreWith(context.Background(), []core.Engine{hung, ok}, nil, dir, ScoreOptions{OutDir: t.TempDir(), EngineTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Engines[0].Error, "deadline") {
		t.Errorf("the hung engine's error is %q", res.Engines[0].Error)
	}
	if res.Engines[1].TP != 1 {
		t.Error("the engine after the hung one was not scored")
	}
}

func TestScoreNotesAKeyringMismatch(t *testing.T) {
	dir, _ := handTruth(t)
	other := KeyringFor(99) // an engine fingerprinting with a different salt
	e := &fakeEngine{name: "e", avail: true, hits: []core.Hit{hit("e", other.FP("value-p1"), "a.env", 2), hit("e", other.FP("value-p2"), "b.py", 4)}}
	res, err := ScoreWith(context.Background(), []core.Engine{e}, nil, dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "keyring") {
		t.Errorf("a keyring mismatch went unnoticed: %v", res.Notes)
	}
}

// naiveMatcher is a reference known-secret matcher for the scorer's tests: every registered
// value and its encodings, found by a 16-byte suffix index. The real one lives in
// internal/known.
type naiveMatcher struct {
	kr      *fp.Keyring
	bySufix map[string][]naiveEntry
	n       int
}

type naiveEntry struct {
	pat     string
	variant string
	fp      string
	raw     string
}

func newNaive(c *Corpus) *naiveMatcher {
	m := &naiveMatcher{kr: c.Key, bySufix: map[string][]naiveEntry{}}
	for _, s := range c.Secrets() {
		for _, f := range registeredForms(s.Raw) {
			if len(f.Pattern) < 16 {
				continue
			}
			k := f.Pattern[len(f.Pattern)-16:]
			m.bySufix[k] = append(m.bySufix[k], naiveEntry{pat: f.Pattern, variant: f.Variant, fp: s.FP, raw: s.Raw})
			m.n++
		}
	}
	return m
}

func (m *naiveMatcher) Len() int { return m.n }

func (m *naiveMatcher) Match(data []byte) []core.KnownMatch {
	var out []core.KnownMatch
	for i := 16; i <= len(data); i++ {
		for _, e := range m.bySufix[string(data[i-16:i])] {
			if i >= len(e.pat) && string(data[i-len(e.pat):i]) == e.pat {
				out = append(out, core.KnownMatch{EntryID: fp.ID(e.fp), Name: "BENCH", Variant: e.variant, Offset: i - len(e.pat), Len: len(e.raw), FP: e.fp, Shape: fp.Shape(e.raw)})
			}
		}
	}
	return out
}

func TestScoreKnownMatcher(t *testing.T) {
	c := sharedCorpus(t)
	m := newNaive(c)
	res, err := ScoreWith(context.Background(), nil, m, c.Dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	k := res.Engines[0]
	if k.Name != "known" || k.Error != "" {
		t.Fatalf("known column: %+v", k)
	}
	byID := map[string]Plant{}
	for _, p := range c.Truth.Plants {
		byID[p.ID] = p
	}
	missed := map[string]bool{}
	for _, id := range append(append([]string{}, k.Missed...), k.MissedOther...) {
		missed[id] = true
	}
	known, found := 0, 0
	for _, p := range c.Truth.Plants {
		if !p.Positive {
			continue
		}
		if p.Known {
			known++
			if missed[p.ID] {
				t.Errorf("%s: a matcher holding the value must find it (variant %s)", p.ID, p.Variant)
			} else {
				found++
			}
		} else if !missed[p.ID] {
			t.Errorf("%s: found although no registered encoding is present in the file", p.ID)
		}
	}
	if known < 250 {
		t.Errorf("only %d plants are known-by-design", known)
	}
	if k.FPNegative+k.FPExtent+k.FPOther != 0 {
		t.Errorf("a confirmed matcher reported %d false positives", k.FPNegative+k.FPExtent+k.FPOther)
	}
	t.Logf("known matcher: %d/%d known-by-design plants, %d entries, 0 false positives", found, known, m.Len())
}

// A key pasted into a commit message lives in the commit object and in no blob; the known scan
// has to read commits too, or `git log` shows the leak and the full scan does not.
func TestKnownScanReadsCommitMessages(t *testing.T) {
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if _, err := git(repo, nil, args...); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("nothing here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "a.txt")
	g := &Gen{r: newRand(11, "commit-message")}
	secret := g.token(4.0, lit("ghp_"), rnd(alnum, 36))
	run("-c", "user.name=t", "-c", "user.email=t@bench.invalid", "commit", "-q", "-m", "wip\n\ntried it with\n"+secret+"\nand it worked")

	kr := KeyringFor(1)
	m := &oneSecret{raw: secret, fp: kr.FP(secret)}
	tmpl := core.Location{Source: "local:" + repo, Kind: "repo", Visibility: core.Local}
	hits, err := scanKnown(context.Background(), repo, m, tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].FP != kr.FP(secret) {
		t.Fatalf("got %d hits, want the one in the commit message", len(hits))
	}
	if hits[0].Loc.Kind != "commit" || hits[0].Loc.Line != 4 {
		t.Errorf("hit is a %s at line %d, want line 4 of the commit message", hits[0].Loc.Kind, hits[0].Loc.Line)
	}
}

// oneSecret is the smallest KnownMatcher: one value, found by substring.
type oneSecret struct{ raw, fp string }

func (o *oneSecret) Len() int { return 1 }
func (o *oneSecret) Match(data []byte) []core.KnownMatch {
	var out []core.KnownMatch
	for off := 0; ; {
		i := bytes.Index(data[off:], []byte(o.raw))
		if i < 0 {
			return out
		}
		out = append(out, core.KnownMatch{EntryID: fp.ID(o.fp), Name: "BENCH", Variant: "raw", Offset: off + i, Len: len(o.raw), FP: o.fp, Shape: fp.Shape(o.raw)})
		off += i + len(o.raw)
	}
}

func TestSimpleTriage(t *testing.T) {
	kr := KeyringFor(1)
	keep := SimpleTriage(kr)
	cases := []struct {
		name string
		h    core.Hit
		want bool
	}{
		{"real token", core.Hit{Rule: "github-pat", Entropy: 4.9, Len: 40, Shape: "ghp_…ab12", Context: `GITHUB_TOKEN = "«ghp_…ab12»"`}, true},
		{"placeholder entropy", core.Hit{Rule: "anthropic-api-key", Entropy: 1.2, Len: 108, Shape: "sk-ant-api03-…"}, false},
		{"example marker", core.Hit{Rule: "aws-access-token", Entropy: 3.6, Len: 20, Context: "# example: «AKIA…»"}, false},
		{"your- marker", core.Hit{Rule: "generic-api-key", Entropy: 3.9, Len: 24, Context: "API_KEY=your-key-here"}, false},
		{"sampler is not sample", core.Hit{Rule: "github-pat", Entropy: 4.7, Len: 40, Context: "sampler_token = «ghp_…»"}, true},
		{"stripe publishable", core.Hit{Rule: "generic-api-key", Entropy: 4.9, Len: 107, Shape: "pk_live_…JSTE"}, false},
		{"posthog project key", core.Hit{Rule: "posthog-project-api-key", Entropy: 4.9, Len: 47, Shape: "phc_…pkT0"}, false},
		{"uuid under a generic rule", core.Hit{Rule: "generic-api-key", Entropy: 3.7, Len: 36}, false},
		{"digest under a generic rule", core.Hit{Rule: "generic-api-key", Entropy: 4.9, Len: 88, Context: "integrity «…»"}, false},
		{"generic with real entropy", core.Hit{Rule: "generic-api-key", Entropy: 4.9, Len: 44, Context: `api_key = "«…»"`}, true},
		{"generic with low entropy", core.Hit{Rule: "generic-api-key", Entropy: 3.6, Len: 40}, false},
		{"verified live always alerts", core.Hit{Rule: "generic-api-key", Entropy: 1.0, Len: 20, Verified: core.Live}, true},
		{"learned local secret always alerts", core.Hit{Rule: "known:raw", Entropy: 0, Len: 20, Known: "kg123456 OPENAI_API_KEY"}, true},
	}
	for _, tc := range cases {
		if got := keep(tc.h); got != tc.want {
			t.Errorf("%s: keep = %v, want %v", tc.name, got, tc.want)
		}
	}
	for i, s := range publicSamples() {
		if keep(core.Hit{Rule: "jwt", FP: kr.FP(s), Entropy: 4.8, Len: len(s)}) {
			t.Errorf("public sample %d was not triaged away", i)
		}
	}
}

// Nothing the bench writes may carry a planted value: fingerprints and display shapes only.
func TestOutputsCarryNoRawValues(t *testing.T) {
	c := sharedCorpus(t)
	out := t.TempDir()
	// an engine that reports every positive plant by fingerprint, as a normalizer would
	var hits []core.Hit
	for _, s := range c.Secrets() {
		hits = append(hits, core.Hit{Engine: "all", Rule: "r", Type: "t", FP: s.FP, Shape: fp.Shape(s.Raw), Len: len(s.Raw),
			Context: fp.Context("X="+s.Raw, s.Raw), Loc: core.Location{Path: "p", Line: 1}})
	}
	hits = append(hits, core.Hit{Engine: "all", Rule: "r", FP: "noise", Shape: "x…", Loc: core.Location{Path: "q", Line: 1}})
	res, err := ScoreWith(context.Background(), []core.Engine{&fakeEngine{name: "all", avail: true, hits: hits}}, newNaive(c), c.Dir, ScoreOptions{OutDir: out})
	if err != nil {
		t.Fatal(err)
	}
	if res.Engines[0].TP != len(c.Secrets()) {
		t.Fatalf("TP %d of %d", res.Engines[0].TP, len(c.Secrets()))
	}
	files := []string{filepath.Join(out, "results.json"), filepath.Join(out, "results.md"), filepath.Join(c.Dir, "truth.json")}
	for _, name := range files {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range c.recs {
			for _, v := range []string{p.fake.Raw, p.fake.Value} {
				if len(v) >= 12 && bytes.Contains(b, []byte(v)) {
					t.Errorf("%s carries the planted value of %s", filepath.Base(name), p.id)
				}
			}
		}
	}
}
