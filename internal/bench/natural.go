package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// Corpus C (STEAL P0-23) is natural code with no secrets planted: at least a gigabyte of public
// code kept in ~/.keyguard/cache/bench, one directory per repository, never in git. Every
// report on it is presumed false until a reviewer says otherwise, so what it measures is
// noise: false alerts per megabyte and per line, which is the number that decides what
// precision a scanner has where secrets are rare (P0-25).

// NaturalRepo is one repository of corpus C.
type NaturalRepo struct {
	Name  string `json:"name"`
	Dir   string `json:"dir"`
	Half  string `json:"half"`
	Bytes int64  `json:"bytes"`
	Lines int    `json:"lines"`
	Files int    `json:"files"`
}

// LoadNatural lists the repositories under root, one per subdirectory (a link to a directory
// counts), and measures them. The corpus must not sit in a git work tree: public code that is
// full of lookalike keys has no business in a repository whose own scanners would then trip.
func LoadNatural(root string) ([]NaturalRepo, error) {
	if insideWorkTree(root) {
		return nil, fmt.Errorf("bench: %s is inside a git work tree; corpus C belongs under ~/.keyguard/cache/bench, in no repository", root)
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var repos []NaturalRepo
	for _, e := range ents {
		dir := filepath.Join(root, e.Name())
		st, err := os.Stat(dir) // through links
		if err != nil || !st.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		real, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return nil, err
		}
		r := NaturalRepo{Name: e.Name(), Dir: real, Half: Half(e.Name())}
		if err := measureTree(real, &r); err != nil {
			return nil, err
		}
		repos = append(repos, r)
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].Name < repos[j].Name })
	return repos, nil
}

// measureTree counts the files, bytes and lines under dir, leaving out .git.
func measureTree(dir string, r *NaturalRepo) error {
	buf := make([]byte, 1<<20)
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		r.Files++
		for {
			n, err := f.Read(buf)
			r.Bytes += int64(n)
			r.Lines += bytes.Count(buf[:n], []byte("\n"))
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
		}
	})
}

// NaturalOptions tunes ScoreNatural.
type NaturalOptions struct {
	// Keep is the pipeline's triage: false for a report that should not alert. Nil uses SimpleTriage
	// with the corpus keyring KeyringFor(0), which only matters for its list of public samples.
	Keep          func(core.Hit) bool
	Rules         string
	EngineTimeout time.Duration
	// Recall is the recall to assume when turning false alerts into precision at a low
	// prevalence: the pipeline's recall on the planted corpus, normally.
	Recall float64
	// SamplePer is how many alerts per type go into the stratified sample the pipeline's precision
	// is estimated from (zero means 25). Judge says whether a sampled alert is a real secret under the
	// label policy (public-by-design is info, a test fixture's key is low, neither is a false
	// alert); nil leaves the sample unjudged for a reviewer.
	SamplePer int
	Judge     func(core.Hit) bool
	Seed      uint64
	SpeedRuns int
}

// NaturalHalf is the noise in one half of corpus C.
type NaturalHalf struct {
	Bytes    int64   `json:"bytes"`
	Lines    int     `json:"lines"`
	Reported int     `json:"reported"`
	Alerts   int     `json:"alerts"`
	PerMB    float64 `json:"alerts_per_mb"`
}

// NaturalEngine is one engine's noise on corpus C.
type NaturalEngine struct {
	Name    string  `json:"name"`
	Version string  `json:"version,omitempty"`
	Skipped string  `json:"skipped,omitempty"`
	Error   string  `json:"error,omitempty"`
	Seconds float64 `json:"seconds"`
	// Reported is distinct fingerprints the engine raised and Alerts the ones that survived
	// triage; FPPerMB and AlertsPerMB divide them by the megabytes scanned.
	Reported       int                    `json:"reported"`
	Alerts         int                    `json:"alerts"`
	FPPerMB        float64                `json:"fp_per_mb"`
	AlertsPerMB    float64                `json:"alerts_per_mb"`
	AlertsPerMLine float64                `json:"alerts_per_mline"`
	PrecisionAt    map[string]float64     `json:"precision_at,omitempty"`
	ByHalf         map[string]NaturalHalf `json:"by_half"`
	ByRule         map[string]int         `json:"alerts_by_rule,omitempty"`
}

// SampledAlert is an alert drawn for review, in display form.
type SampledAlert struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Rule  string `json:"rule"`
	Repo  string `json:"repo"`
	Path  string `json:"path"`
	Line  int    `json:"line"`
	Shape string `json:"shape"`
}

// NaturalResult is the noise of the engines and of the pipeline on corpus C.
type NaturalResult struct {
	Repos    []NaturalRepo   `json:"repos"`
	MB       float64         `json:"mb"`
	Lines    int             `json:"lines"`
	Engines  []NaturalEngine `json:"engines"`
	Pipeline NaturalEngine   `json:"pipeline"`
	Sample   []SampledAlert  `json:"sample,omitempty"`
	Strata   []Stratum       `json:"strata,omitempty"`
	// Precision is the pipeline's precision on the alerts, estimated from the sample once it has
	// been judged: Wilson at the effective sample size, or the rule of three when no sampled
	// alert was false.
	Precision *Estimate     `json:"precision,omitempty"`
	Speed     []SpeedResult `json:"speed,omitempty"`
	Notes     []string      `json:"notes,omitempty"`
}

// ScoreNatural runs every engine over every repo of corpus C in directory mode and counts what it
// reports. It scores noise and nothing else: there is no truth to compare with.
func ScoreNatural(ctx context.Context, engines []core.Engine, repos []NaturalRepo, o NaturalOptions) (*NaturalResult, error) {
	keep := o.Keep
	if keep == nil {
		keep = SimpleTriage(KeyringFor(0))
	}
	timeout := o.EngineTimeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	res := &NaturalResult{Repos: repos}
	halfBytes, halfLines := map[string]int64{}, map[string]int{}
	for _, r := range repos {
		res.MB += float64(r.Bytes) / 1e6
		res.Lines += r.Lines
		halfBytes[r.Half] += r.Bytes
		halfLines[r.Half] += r.Lines
	}

	type alert struct {
		hit  core.Hit
		repo string
	}
	var pipeline []alert
	seenPipe := map[string]bool{}
	for _, e := range engines {
		ne := NaturalEngine{Name: e.Name(), Version: e.Version(), ByHalf: map[string]NaturalHalf{}}
		if !e.Available() {
			ne.Skipped = "binary not available"
			res.Engines = append(res.Engines, ne)
			continue
		}
		reported, alerts := map[string]string{}, map[string]string{} // fingerprint -> half
		ne.ByRule = map[string]int{}
		unsupported := false
		for _, r := range repos {
			var mu sync.Mutex
			ectx, cancel := context.WithTimeout(ctx, timeout)
			start := time.Now()
			err := e.ScanDir(ectx, r.Dir, core.ScanOpts{
				Loc:   core.Location{Source: "natural:" + r.Name, Kind: "file", Visibility: core.Public},
				Rules: o.Rules,
			}, func(h core.Hit) {
				mu.Lock()
				defer mu.Unlock()
				key := h.FP
				if key == "" {
					key = "loc:" + h.Loc.Key()
				}
				if _, dup := reported[key]; !dup {
					reported[key] = r.Half
				}
				if _, dup := alerts[key]; !dup && keep(h) {
					alerts[key] = r.Half
					ne.ByRule[h.Rule]++
					if !seenPipe[key] {
						seenPipe[key] = true
						pipeline = append(pipeline, alert{h, r.Name})
					}
				}
			})
			cancel()
			ne.Seconds += time.Since(start).Seconds()
			if err == core.ErrUnsupported {
				unsupported = true
				break
			}
			if err != nil && ne.Error == "" {
				ne.Error = fmt.Sprintf("%s: %v", r.Name, err)
			}
		}
		if unsupported {
			ne.Skipped = "no directory mode"
			res.Engines = append(res.Engines, ne)
			continue
		}
		res.finishNatural(&ne, reported, alerts, halfBytes, halfLines, o.Recall)
		res.Engines = append(res.Engines, ne)

		if o.SpeedRuns > 0 {
			for _, r := range repos {
				res.Speed = append(res.Speed, MeasureSpeed(ctx, e.Name(), e.Version(), r.Name, o.SpeedRuns, func(ctx context.Context) error {
					ectx, cancel := context.WithTimeout(ctx, timeout)
					defer cancel()
					return e.ScanDir(ectx, r.Dir, core.ScanOpts{Loc: core.Location{Source: "natural:" + r.Name, Kind: "file", Visibility: core.Public}, Rules: o.Rules}, func(core.Hit) {})
				}))
			}
		}
	}

	// the pipeline: every distinct alert any engine raised, sampled by type for review
	pe := NaturalEngine{Name: "pipeline", ByHalf: map[string]NaturalHalf{}}
	reported, alerts := map[string]string{}, map[string]string{}
	var hits []core.Hit
	byRepoHalf := map[string]string{}
	for _, r := range repos {
		byRepoHalf[r.Name] = r.Half
	}
	for _, a := range pipeline {
		key := a.hit.FP
		if key == "" {
			key = "loc:" + a.hit.Loc.Key()
		}
		reported[key], alerts[key] = byRepoHalf[a.repo], byRepoHalf[a.repo]
		hits = append(hits, a.hit)
	}
	res.finishNatural(&pe, reported, alerts, halfBytes, halfLines, o.Recall)
	res.Pipeline = pe

	per := o.SamplePer
	if per <= 0 {
		per = 25
	}
	sample, strata := SampleAlerts(hits, per, o.Seed)
	repoOf := map[string]string{}
	for _, a := range pipeline {
		repoOf[a.hit.FP+"|"+a.hit.Loc.Key()] = a.repo
	}
	for _, h := range sample {
		res.Sample = append(res.Sample, SampledAlert{ID: fp.ID(h.FP), Type: h.Type, Rule: h.Rule, Repo: repoOf[h.FP+"|"+h.Loc.Key()], Path: h.Loc.Path, Line: h.Loc.Line, Shape: h.Shape})
	}
	if o.Judge != nil {
		strata = Judge(sample, strata, o.Judge)
		est := Stratified(strata)
		res.Precision = &est
	} else if len(sample) > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d sampled alerts are waiting for a verdict; the pipeline's precision cannot be estimated without one", len(sample)))
	}
	res.Strata = strata
	return res, nil
}

// finishNatural fills the rates of an engine from its sets of distinct reports and alerts.
func (r *NaturalResult) finishNatural(ne *NaturalEngine, reported, alerts map[string]string, halfBytes map[string]int64, halfLines map[string]int, recall float64) {
	ne.Reported, ne.Alerts = len(reported), len(alerts)
	if r.MB > 0 {
		ne.FPPerMB = float64(ne.Reported) / r.MB
		ne.AlertsPerMB = float64(ne.Alerts) / r.MB
	}
	if r.Lines > 0 {
		ne.AlertsPerMLine = float64(ne.Alerts) / float64(r.Lines) * 1e6
		ne.PrecisionAt = map[string]float64{}
		for _, prev := range Prevalences {
			ne.PrecisionAt[prevalenceLabel(prev)] = PrecisionAt(prev, recall, float64(ne.Alerts)/float64(r.Lines))
		}
	}
	for _, h := range []string{HalfTune, HalfHeldOut} {
		nh := NaturalHalf{Bytes: halfBytes[h], Lines: halfLines[h]}
		for _, half := range reported {
			if half == h {
				nh.Reported++
			}
		}
		for _, half := range alerts {
			if half == h {
				nh.Alerts++
			}
		}
		if nh.Bytes > 0 {
			nh.PerMB = float64(nh.Alerts) / (float64(nh.Bytes) / 1e6)
		}
		ne.ByHalf[h] = nh
	}
}

// WriteTo writes natural.json and natural.md into dir.
func (r *NaturalResult) WriteTo(dir string) error {
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "natural.json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "natural.md"), []byte(r.Markdown()), 0o644)
}

// Markdown renders corpus C's noise. It lists sampled alerts by id, type, rule and place, never by value.
func (r *NaturalResult) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# keyguard bench: natural code\n\n%d repos, %.0f MB, %d lines, no secret planted. Every report is a false alert until a reviewer says otherwise.\n\n", len(r.Repos), r.MB, r.Lines)
	b.WriteString("| engine | version | seconds | reported | alerts | reports per MB | alerts per MB | alerts per Mline | tune alerts per MB | held-out alerts per MB | precision at 1e-3 | 1e-5 | 1e-6 |\n|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|\n")
	rows := append(append([]NaturalEngine{}, r.Engines...), r.Pipeline)
	for _, e := range rows {
		if e.Skipped != "" {
			fmt.Fprintf(&b, "| %s | %s | skipped: %s ||||||||||||\n", e.Name, e.Version, e.Skipped)
			continue
		}
		fmt.Fprintf(&b, "| %s | %s | %.2f | %d | %d | %.3f | %.3f | %.1f | %.3f | %.3f | %s | %s | %s |\n", e.Name, e.Version, e.Seconds, e.Reported, e.Alerts,
			e.FPPerMB, e.AlertsPerMB, e.AlertsPerMLine, e.ByHalf[HalfTune].PerMB, e.ByHalf[HalfHeldOut].PerMB,
			pct(e.PrecisionAt["1e-3"]), pct(e.PrecisionAt["1e-5"]), pct(e.PrecisionAt["1e-6"]))
	}
	if p := r.Precision; p != nil {
		how := "Wilson at the effective sample size"
		if p.ZeroFP {
			how = "rule of three: no sampled alert was false"
		}
		if p.Census {
			how = "every alert was judged"
		}
		fmt.Fprintf(&b, "\nPipeline precision from %d sampled alerts: %s, 95%% interval %s to %s (%s).\n", p.Sampled, pct(p.Precision), pct(p.Lo), pct(p.Hi), how)
	}
	if len(r.Strata) > 0 {
		b.WriteString("\n## Sample\n\n| type | alerts | sampled | real |\n|---|--:|--:|--:|\n")
		for _, s := range r.Strata {
			fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", s.Name, s.Population, s.Sampled, s.TP)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "\n> %s\n", n)
	}
	return b.String()
}
