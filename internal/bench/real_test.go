package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"keyguard/internal/core"
	"keyguard/rules"
)

func realEngines(t *testing.T, c *Corpus, names ...string) []core.Engine {
	t.Helper()
	var out []core.Engine
	for _, n := range names {
		switch n {
		case "betterleaks":
			out = append(out, newLeaks(n, engineBin(t, "betterleaks"), c.Key))
		case "gitleaks":
			out = append(out, newLeaks(n, engineBin(t, "gitleaks"), c.Key))
		case "trufflehog":
			out = append(out, newTrufflehog(engineBin(t, "trufflehog"), c.Key))
		}
	}
	return out
}

func byName(res *Results, name string) EngineResult {
	for _, e := range res.Engines {
		if e.Name == name {
			return e
		}
	}
	return EngineResult{}
}

// Betterleaks is the primary regex engine: every plant its own rules cover as planted must be
// reported, in every location and encoding the corpus uses.
func TestBetterleaksOnCorpus(t *testing.T) {
	c := sharedCorpus(t)
	out := t.TempDir()
	res, err := ScoreWith(context.Background(), realEngines(t, c, "betterleaks"), nil, c.Dir, ScoreOptions{OutDir: out})
	if err != nil {
		t.Fatal(err)
	}
	e := res.Engines[0]
	if e.Error != "" || e.Skipped != "" || e.Version == "" {
		t.Fatalf("betterleaks did not run: error=%q skipped=%q version=%q", e.Error, e.Skipped, e.Version)
	}
	t.Logf("corpus: %d commits, %d files, %d objects, %.1f MB, %d refs, %d positives (%d detectable), %d negatives",
		res.Corpus.Commits, res.Corpus.Files, res.Corpus.Blobs, float64(res.Corpus.Bytes)/1e6, res.Corpus.Refs, res.Corpus.Positives, res.Corpus.Detectable, res.Corpus.Negatives)
	t.Logf("betterleaks %s: %.2fs, %d hits, recall %.1f%% (%d/%d detectable), own-rules recall %.1f%% (%d/%d), all-plant recall %.1f%%, precision %.1f%% (tp %d, fp: %d negative %d extent %d other)",
		e.Version, e.Seconds, e.Hits, 100*e.Recall, e.FoundDetectable, e.Detectable, 100*e.RecallOwn, e.OwnFound, e.OwnDetectable, 100*e.RecallAll, 100*e.Precision, e.TP, e.FPNegative, e.FPExtent, e.FPOther)

	if e.OwnDetectable < 200 {
		t.Fatalf("only %d plants are covered by betterleaks rules", e.OwnDetectable)
	}
	if e.RecallOwn < 0.99 {
		t.Errorf("betterleaks missed plants its own rules cover: %v", e.OwnMissed)
	}
	if e.Recall < 0.95 || e.Precision < 0.9 {
		t.Errorf("recall %.3f precision %.3f", e.Recall, e.Precision)
	}
	// every ref, every history shape: the engine must see all of them
	for _, v := range []string{vBranch, vTag, vPull, vDeleted, vBigfile, vZip, vB64, vKeyFile} {
		if r := e.ByVariant[v]; r == nil || r.Detectable == 0 || r.FoundDetectable != r.Detectable {
			t.Errorf("variant %s: found %+v", v, r)
		}
	}
	for _, f := range []string{"results.json", "results.md"} {
		if st, err := os.Stat(filepath.Join(out, f)); err != nil || st.Size() == 0 {
			t.Errorf("%s was not written", f)
		}
	}
	md, _ := os.ReadFile(filepath.Join(out, "results.md"))
	if !strings.Contains(string(md), "| betterleaks | "+e.Version) {
		t.Error("results.md does not tabulate betterleaks")
	}
	checkNoRaw(t, c, filepath.Join(out, "results.json"), filepath.Join(out, "results.md"))
}

// A different seed is a different corpus of the same shape; the score should hold.
func TestBetterleaksOnAnotherSeed(t *testing.T) {
	c, err := Generate(filepath.Join(t.TempDir(), "s2"), Options{Seed: 2})
	if err != nil {
		t.Fatal(err)
	}
	res, err := ScoreWith(context.Background(), realEngines(t, c, "betterleaks"), nil, c.Dir, ScoreOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	e := res.Engines[0]
	t.Logf("seed 2, betterleaks: own-rules recall %.1f%% (%d/%d), precision %.1f%%", 100*e.RecallOwn, e.OwnFound, e.OwnDetectable, 100*e.Precision)
	if e.RecallOwn < 0.97 {
		t.Errorf("seed 2: betterleaks missed %v", e.OwnMissed)
	}
}

// The loop the bench exists for: a gap it lists is closed by a rule, and the next run shows it.
// Tavily has no engine rule, so its plants are a gap; an extra betterleaks rule finds them.
func TestExtraRulesCloseAListedGap(t *testing.T) {
	c := sharedCorpus(t)
	rules := filepath.Join(t.TempDir(), "extra.toml")
	body := `title = "bench extra rules"

[extend]
useDefault = true

[[rules]]
id = "tavily-api-key"
description = "Tavily API key"
regex = '''\b(tvly-(?:dev|prod)-[A-Za-z0-9]{32})\b'''
keywords = ["tvly-"]
`
	if err := os.WriteFile(rules, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	score := func(extra string) EngineResult {
		res, err := ScoreWith(context.Background(), realEngines(t, c, "betterleaks"), nil, c.Dir, ScoreOptions{OutDir: t.TempDir(), Rules: extra})
		if err != nil {
			t.Fatal(err)
		}
		if res.Engines[0].Error != "" {
			t.Fatalf("betterleaks: %s", res.Engines[0].Error)
		}
		return res.Engines[0]
	}
	tavily := func(e EngineResult) int {
		if ts := e.ByType["tavily"]; ts != nil {
			return ts.Found
		}
		return 0
	}
	before, after := score(""), score(rules)
	t.Logf("tavily plants found by betterleaks: %d/%d without the rule, %d/%d with it; precision %.1f%% -> %.1f%%",
		tavily(before), before.ByType["tavily"].Total, tavily(after), after.ByType["tavily"].Total, 100*before.Precision, 100*after.Precision)
	if tavily(before) != 0 {
		t.Errorf("betterleaks found %d tavily plants with no rule for them", tavily(before))
	}
	if total := after.ByType["tavily"].Total; total == 0 || tavily(after) != total {
		t.Errorf("the extra rule found %d of %d tavily plants", tavily(after), total)
	}
	if after.Found <= before.Found {
		t.Errorf("the extra rule changed nothing: %d -> %d plants found", before.Found, after.Found)
	}
}

// The acceptance shape: all engines plus the known matcher, then the pipeline.
func TestRealEnginesUnionAndPipeline(t *testing.T) {
	c := sharedCorpus(t)
	out := t.TempDir()
	res, err := ScoreWith(context.Background(), realEngines(t, c, "betterleaks", "gitleaks", "trufflehog"), newNaive(c), c.Dir, ScoreOptions{OutDir: out})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Engines {
		if e.Error != "" || e.Skipped != "" {
			t.Fatalf("%s: error=%q skipped=%q", e.Name, e.Error, e.Skipped)
		}
		t.Logf("%-12s %.2fs  hits %4d  recall %5.1f%% (%d/%d)  precision %5.1f%%", e.Name, e.Seconds, e.Hits, 100*e.Recall, e.FoundDetectable, e.Detectable, 100*e.Precision)
	}
	u, p := res.Union, res.Pipeline
	t.Logf("%-12s %.2fs  recall %5.1f%%  precision %5.1f%%  fp: %d negative %d extent %d other", "union", u.Seconds, 100*u.Recall, 100*u.Precision, u.FPNegative, u.FPExtent, u.FPOther)
	t.Logf("%-12s %.2fs  recall %5.1f%%  precision %5.1f%%  fp: %d negative %d extent %d other", "pipeline", p.Seconds, 100*p.Recall, 100*p.Precision, p.FPNegative, p.FPExtent, p.FPOther)

	if u.Recall < 0.98 {
		t.Errorf("union recall %.3f; missed %v", u.Recall, u.Missed)
	}
	if p.Recall < 0.98 {
		t.Errorf("pipeline recall %.3f; triage dropped %v", p.Recall, diff(p.Missed, u.Missed))
	}
	if p.Precision < 0.95 {
		t.Errorf("pipeline precision %.3f; false positives: %d negative, %d extent, %d other", p.Precision, p.FPNegative, p.FPExtent, p.FPOther)
	}
	if p.Precision <= u.Precision {
		t.Errorf("triage did not improve precision: union %.3f pipeline %.3f", u.Precision, p.Precision)
	}
	if res.SequentialSeconds <= 0 || res.ParallelSeconds <= 0 || res.ParallelSeconds > res.SequentialSeconds {
		t.Errorf("timing: sequential %.2fs parallel %.2fs", res.SequentialSeconds, res.ParallelSeconds)
	}
	// what the regex engines cannot see is listed, and only the known matcher closes it
	gaps := map[string]bool{}
	for _, g := range res.Gaps {
		gaps[g.Type] = true
		if g.Why == "" || len(g.Plants) == 0 {
			t.Errorf("gap %s has no reason or plants", g.Type)
		}
	}
	for _, want := range []string{"tavily", "card", "discord"} {
		if !gaps[want] {
			t.Errorf("no regex engine covers %s, yet it is not listed as a gap", want)
		}
	}
	if p.RecallAll <= u.RecallAll {
		t.Errorf("the known matcher added nothing to the pipeline: %.3f vs %.3f over all plants", p.RecallAll, u.RecallAll)
	}
	k := byName(res, "known")
	if k.FPNegative+k.FPExtent+k.FPOther != 0 || k.KnownFound != k.KnownTotal || k.KnownTotal < 250 {
		t.Errorf("known matcher: %d/%d known-by-design plants, %d false positives", k.KnownFound, k.KnownTotal, k.FPNegative+k.FPExtent+k.FPOther)
	}
	checkNoRaw(t, c, filepath.Join(out, "results.json"), filepath.Join(out, "results.md"))
}

func diff(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// checkNoRaw fails if any written file carries a planted value.
func checkNoRaw(t *testing.T, c *Corpus, files ...string) {
	t.Helper()
	for _, name := range files {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range c.recs {
			if r.positive && len(r.fake.Raw) >= 12 && bytes.Contains(b, []byte(r.fake.Raw)) {
				t.Errorf("%s carries the planted value of %s", filepath.Base(name), r.id)
			}
		}
	}
}

// Invariant 2: this package's source holds no secret-shaped literal, or keyguard's own
// pre-commit hook would block its commit. Every installed engine reads the package.
func TestPackageSourceHoldsNoSecretLiterals(t *testing.T) {
	type tool struct {
		name string
		args []string
	}
	for _, tl := range []tool{
		{"betterleaks", []string{"dir", "--no-banner", "-r", "-", "-f", "json", "--exit-code", "0", "-l", "error", "."}},
		{"gitleaks", []string{"dir", "--no-banner", "-r", "-", "-f", "json", "--exit-code", "0", "-l", "error", "."}},
	} {
		cmd := exec.Command(engineBin(t, tl.name), tl.args...)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v", tl.name, err)
		}
		var fs []struct {
			RuleID    string
			File      string
			StartLine int
		}
		if err := json.Unmarshal(out, &fs); err != nil && len(bytes.TrimSpace(out)) > 0 {
			t.Fatalf("%s: %v", tl.name, err)
		}
		for _, f := range fs {
			t.Errorf("%s flags %s at %s:%d", tl.name, f.RuleID, f.File, f.StartLine)
		}
	}
	th := exec.Command(engineBin(t, "trufflehog"), "filesystem", ".", "--json", "--no-update", "--no-verification", "--no-color", "--log-level=-1")
	out, err := th.Output()
	if err != nil {
		t.Fatalf("trufflehog: %v", err)
	}
	for _, l := range bytes.Split(out, []byte("\n")) {
		var f struct {
			DetectorName   string
			SourceMetadata struct {
				Data struct{ Filesystem struct{ File string } }
			}
		}
		if json.Unmarshal(l, &f) == nil && f.DetectorName != "" {
			t.Errorf("trufflehog flags %s in %s", f.DetectorName, f.SourceMetadata.Data.Filesystem.File)
		}
	}
}

// rules/keyguard.toml was written for gaps this bench listed (Cal.com, Discord, a bare ElevenLabs
// key, an sb_secret_ key...). Loaded as the scan config it must close them without letting
// anything new through: more of the planted keys found, and not more lookalikes reported.
func TestTheShippedRulesCloseGapsAndAddNoNoise(t *testing.T) {
	c := sharedCorpus(t)
	file := filepath.Join(t.TempDir(), "keyguard.toml")
	if err := os.WriteFile(file, rules.KeyguardTOML, 0o600); err != nil {
		t.Fatal(err)
	}
	score := func(rules string) EngineResult {
		res, err := ScoreWith(context.Background(), realEngines(t, c, "betterleaks"), nil, c.Dir, ScoreOptions{OutDir: t.TempDir(), Rules: rules})
		if err != nil {
			t.Fatal(err)
		}
		if res.Engines[0].Error != "" {
			t.Fatalf("betterleaks: %s", res.Engines[0].Error)
		}
		return res.Engines[0]
	}
	before, after := score(""), score(file)
	t.Logf("betterleaks, default rules: found %d of %d plants (%.1f%%), precision %.1f%%, %d lookalikes reported",
		before.Found, before.Positives, 100*before.RecallAll, 100*before.Precision, before.FPNegative)
	t.Logf("betterleaks, with rules/keyguard.toml: found %d of %d plants (%.1f%%), precision %.1f%%, %d lookalikes reported",
		after.Found, after.Positives, 100*after.RecallAll, 100*after.Precision, after.FPNegative)
	if after.Found < before.Found+25 {
		t.Errorf("the shipped rules found %d more plants, want at least 25", after.Found-before.Found)
	}
	for _, ty := range []string{"discord", "calcom", "supabase"} {
		b, a := before.ByType[ty], after.ByType[ty]
		if a == nil || b == nil || a.Found <= b.Found {
			t.Errorf("type %s: found %v with the shipped rules, %v without", ty, a, b)
		}
	}
	if after.FPNegative > before.FPNegative+2 {
		t.Errorf("the shipped rules reported %d more lookalikes", after.FPNegative-before.FPNegative)
	}
	if after.Recall < before.Recall {
		t.Errorf("recall over the plants the default rules cover fell from %.3f to %.3f", before.Recall, after.Recall)
	}
}
