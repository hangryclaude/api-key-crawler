package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"keyguard/internal/bench"
	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/engines"
	"keyguard/internal/fp"
	"keyguard/internal/install"
	"keyguard/internal/known"
	"keyguard/internal/triage"
)

func (c *cli) cmdBench(args []string) int {
	f := c.flagSet("bench", "bench [--seed N] [--scale N] [--engines a,b] [--out DIR] [--keep-corpus] [--json]\n             [--speed N] [--verify] [--oracle] [--natural | --natural-dir DIR]\n\nBuilds a synthetic git repo of planted fakes (83 provider formats in 42 places and encodings, with an\ninvalid twin beside many of them and lookalikes that must not alert) in a temp dir, runs the engines,\nthe learned-secret matcher and the triage over it, and prints recall, precision and time for each and for\nthe pipeline. The 98% target is met only when the corpus is big enough to prove it (300 detectable plants\nin 40 formats with 6 placements each) and the Wilson lower bound clears 98%.\n\n--speed N    time each engine N times over the corpus (the first run cold): wall, CPU and peak memory\n--verify     score the pipeline from a run with verification on (asks provider APIs about fake keys)\n--oracle     also score the engines against the real mirrors: your own learned keys found in the history\n             under the mirrors are the labels, and every miss is a rule to write\n--natural    also measure the noise on public code under <root>/cache/bench (--natural-dir DIR for another)")
	seed := f.Uint64("seed", 1, "the same seed makes the same repo")
	scale := f.Int("scale", 1, "filler multiplier: 1 is about 650 commits")
	engs := f.String("engines", "", "comma-separated engines, or \"all\" (default: the engines of the deep tier in config.json)")
	out := f.String("out", "", "where results.json and results.md go (default <root>/state/bench/<time>)")
	keep := f.Bool("keep-corpus", false, "keep the generated repo (it holds fake secrets only)")
	asJSON := f.Bool("json", false, "print results.json instead of the tables")
	speed := f.Int("speed", 0, "time each engine this many times (the first run cold, the rest warm)")
	verify := f.Bool("verify", false, "score the pipeline from a run with verification on (network)")
	oracle := f.Bool("oracle", false, "score the engines against the real mirrors, with the learned matcher as the oracle")
	natural := f.Bool("natural", false, "also measure false alerts on public code in <root>/cache/bench")
	naturalDir := f.String("natural-dir", "", "like --natural, with the code in this directory")
	if _, code, ok := c.parse(f, args); !ok {
		return code
	}
	if *speed < 0 {
		return c.usageErr(f, "--speed must be at least 1")
	}
	p := c.paths()
	cfg := c.config(p)

	// By default the bench scores what actually runs in the sweeps, so its pipeline row is the
	// number that matters; "all" adds every engine keyguard has, for deciding what to add.
	names := splitList(*engs)
	switch {
	case len(names) == 1 && names[0] == "all":
		names = engines.Names
	case len(names) == 0:
		names = cfg.Tier(install.TierDeep)
	}
	names, wantNative := withoutNative(names)
	if wantNative {
		if len(names) == 0 {
			return c.nativeOnly(*asJSON)
		}
		fmt.Fprintln(c.err, nativeNotBuilt)
	}

	tmp, err := os.MkdirTemp("", "keyguard-bench-")
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	if !*keep {
		defer os.RemoveAll(tmp) // our own temp dir, made a moment ago, holding only fakes
	} else {
		fmt.Fprintf(c.err, "keeping the corpus in %s\n", tmp)
	}
	dir := filepath.Join(tmp, "corpus")
	if *out == "" {
		*out = filepath.Join(p.State, "bench", c.now().UTC().Format("20060102T150405Z"))
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return c.failf("%s", safeErr(err))
	}

	// The engines and the matcher must fingerprint with the corpus's own keyring, or no hit
	// would match a plant.
	kr := bench.KeyringFor(*seed)
	started := time.Now()
	corp, err := bench.Generate(dir, bench.Options{Seed: *seed, Scale: *scale})
	if err != nil {
		return c.failf("building the corpus: %s", safeErr(err))
	}
	fmt.Fprintf(c.err, "corpus: %d commits, %d plants, built in %s\n", corp.Truth.Stats.Commits, corp.Truth.Stats.Positives, secs(time.Since(started).Seconds()))

	var engList []core.Engine
	for _, n := range names {
		e, err := engines.New(n, cfg.EnginePaths()[n], kr, cfg.EngineOptions(p)...)
		if err != nil {
			return c.failf("%s", safeErr(err))
		}
		engList = append(engList, e)
	}
	if wantNative {
		engList = append(engList, notBuilt{}) // a skipped row in the table, scored by nothing
	}

	var entries []known.Entry
	for _, s := range corp.Secrets() {
		entries = append(entries, known.EntriesFor(kr, s.Name, "bench", []byte(s.Raw))...)
	}
	m, err := known.NewMatcher(kr, entries)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}

	rules := ""
	if cfg.Rules != "" {
		if _, err := os.Stat(cfg.Rules); err == nil {
			rules = cfg.Rules
		}
	}
	res, err := bench.ScoreWith(c.ctx, engList, m, dir, bench.ScoreOptions{
		OutDir: *out, Keep: keepAlert(kr), Rules: rules, Verify: *verify, SpeedRuns: *speed,
	})
	if err != nil {
		return c.failf("scoring: %s", safeErr(err))
	}
	if *asJSON {
		c.printJSON(res)
	} else {
		fmt.Fprint(c.out, res.Markdown())
		c.printVerdict(res, names)
	}
	fmt.Fprintf(c.err, "results written to %s\n", *out)

	// Corpus B and C are about this Mac: they read the real mirrors and the real learned store, so
	// they are asked for, and their results go to files beside results.json.
	if *oracle {
		if code := c.benchOracle(p, cfg, rules, *out, *speed); code != exitOK {
			return code
		}
	}
	if *natural || *naturalDir != "" {
		root := *naturalDir
		if root == "" {
			root = filepath.Join(p.Root, "cache", "bench")
		}
		if code := c.benchNatural(cfg, p, kr, engList, root, rules, *out, res.Pipeline.Recall, *speed); code != exitOK {
			return code
		}
	}
	return exitOK
}

// printVerdict is PLAN.md's acceptance line for the engines that were scored. A recall over a
// corpus too small to prove it proves nothing, so the target counts as met only when the gate
// is satisfied and the lower end of the 95% interval clears 98%.
func (c *cli) printVerdict(res *bench.Results, names []string) {
	verdict := "PASS"
	switch {
	case res.Pipeline.Recall < 0.98 || res.Pipeline.Precision < 0.95:
		verdict = "FAIL"
	case !res.Gate.Sufficient:
		verdict = "NOT PROVEN (the corpus is too small to show 98%)"
	case res.Pipeline.RecallLo < 0.98:
		verdict = fmt.Sprintf("NOT PROVEN (recall may be as low as %.1f%% at 95%% confidence)", 100*res.Pipeline.RecallLo)
	}
	fmt.Fprintf(c.out, "\nPlan targets for [%s]: pipeline recall %.1f%% (want 98%%), precision %.1f%% (want 95%%): %s\n",
		strings.Join(names, " "), 100*res.Pipeline.Recall, 100*res.Pipeline.Precision, verdict)
	g := res.Gate
	fmt.Fprintf(c.out, "Gate: %d detectable plants (want %d), %d formats with %d placements or more (want %d): %s\n",
		g.Detectable, bench.GateDetectable, g.FormatsReady, bench.GatePlacements, bench.GateFormats,
		map[bool]string{true: "enough to prove 98%", false: "too thin"}[g.Sufficient])
	if o := res.Overfit; o != nil {
		fmt.Fprintf(c.out, "Overfit gap, tune half against held-out: recall %+.1f points, precision %+.1f points\n", 100*o.RecallGap, 100*o.PrecisionGap)
	}
}

// benchOracle is corpus B: the learned matcher finds the keys that really leaked, in the real
// mirrors, and each engine is scored on how many of them it reports. Engines have to fingerprint
// with the keyring the matcher uses, which is the real one, not the corpus's.
func (c *cli) benchOracle(p core.Paths, cfg install.Config, rules, out string, speed int) int {
	kr, err := openKeyring(p)
	if err != nil {
		return c.failf("%s", safeErr(err))
	}
	m, merr := knownLoad()
	if m == nil || m.Len() == 0 {
		return c.failf("--oracle needs learned secrets to score against; run `keyguard learn` first%s", map[bool]string{true: " (" + safeErr(merr) + ")", false: ""}[merr != nil])
	}
	var engList []core.Engine
	for _, n := range cfg.Tier(install.TierDeep) {
		if e, err := engines.New(n, cfg.EnginePaths()[n], kr, cfg.EngineOptions(p)...); err == nil && e.Available() {
			engList = append(engList, e)
		}
	}
	root := cfg.MirrorRoot(p)
	dirs, _ := filepath.Glob(filepath.Join(root, "*", "*", "*.git"))
	var mirrors []bench.OracleMirror
	for _, d := range dirs {
		owner, name := filepath.Base(filepath.Dir(d)), strings.TrimSuffix(filepath.Base(d), ".git")
		mirrors = append(mirrors, bench.OracleMirror{Name: owner + "/" + name, Dir: d})
	}
	if len(mirrors) == 0 {
		return c.failf("--oracle found no mirrors under %s; run `keyguard sync`", c.tilde(root))
	}
	res, err := bench.ScoreOracle(c.ctx, engList, m, mirrors, bench.OracleOptions{Rules: rules, SpeedRuns: speed})
	if err != nil {
		return c.failf("oracle: %s", safeErr(err))
	}
	if err := res.WriteTo(out); err != nil {
		return c.failf("oracle: %s", safeErr(err))
	}
	fmt.Fprintf(c.out, "\noracle: %d leaked keys of yours in %d mirrors; written to %s/oracle.json (held-out misses are counted there, not listed)\n", res.Secrets, res.Mirrors, c.tilde(out))
	return exitOK
}

// benchNatural is corpus C: false alerts on public code, where there is nothing to find.
func (c *cli) benchNatural(cfg install.Config, p core.Paths, kr core.Fingerprinter, engList []core.Engine, root, rules, out string, recall float64, speed int) int {
	repos, err := bench.LoadNatural(root)
	if err != nil {
		return c.failf("--natural: %s", safeErr(err))
	}
	if len(repos) == 0 {
		return c.failf("--natural: %s holds no code; put public repositories there, one directory each, outside any git repository", c.tilde(root))
	}
	res, err := bench.ScoreNatural(c.ctx, engList, repos, bench.NaturalOptions{Keep: keepAlert(kr), Rules: rules, Recall: recall, SpeedRuns: speed})
	if err != nil {
		return c.failf("natural: %s", safeErr(err))
	}
	if err := res.WriteTo(out); err != nil {
		return c.failf("natural: %s", safeErr(err))
	}
	fmt.Fprintf(c.out, "\nnatural: %s of public code (%d repos, %d lines); written to %s/natural.json\n", fmt.Sprintf("%.0f MB", res.MB), len(repos), res.Lines, c.tilde(out))
	return exitOK
}

// keepAlert is the pipeline's triage: the real classifier, run on what a Hit still carries
// once its value is gone. A hit that ends below low severity is not an alert.
func keepAlert(kr core.Fingerprinter) func(core.Hit) bool {
	return func(h core.Hit) bool {
		s := core.Secret{
			FP: h.FP, ID: fp.ID(h.FP), Type: h.Type, Shape: h.Shape, Len: h.Len,
			Engines: []string{h.Engine}, Rules: []string{h.Rule}, Locations: []core.Location{h.Loc},
			Verified: h.Verified, Known: h.Known, Triage: triage.Unreviewed, Status: db.StatusOpen,
		}
		tr := triage.New(
			triage.WithFingerprinter(kr),
			triage.WithEvidence(func(string) (triage.Evidence, bool) {
				return triage.Evidence{Contexts: []string{h.Context}, Entropy: h.Entropy}, true
			}),
		)
		tr.Classify(&s)
		return s.Severity >= core.Low
	}
}
