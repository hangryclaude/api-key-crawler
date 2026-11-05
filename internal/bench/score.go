package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
)

// Rate is found/total for one slice of the plants.
type Rate struct {
	Total           int     `json:"total"`
	Found           int     `json:"found"`
	Recall          float64 `json:"recall"`
	Detectable      int     `json:"detectable"`
	FoundDetectable int     `json:"found_detectable"`
	// DetectableRecall is found_detectable over detectable, the figure the acceptance target is
	// about, with its 95% Wilson interval. A type of a few plants has a wide one (STEAL P0-25).
	DetectableRecall float64 `json:"detectable_recall"`
	DetectableLo     float64 `json:"detectable_lo"`
	DetectableHi     float64 `json:"detectable_hi"`
}

// finish fills the derived fields once the counts are in.
func (r *Rate) finish() {
	r.Recall = ratio(r.Found, r.Total)
	r.DetectableRecall = ratio(r.FoundDetectable, r.Detectable)
	r.DetectableLo, r.DetectableHi = Wilson(r.FoundDetectable, r.Detectable)
}

// HalfScore is one half of the corpus, tune or held-out (STEAL P0-23). Rules may be fitted to
// the misses of the tune half only; the held-out half is read as a score and nothing else.
type HalfScore struct {
	Positives       int     `json:"positives"`
	Detectable      int     `json:"detectable"`
	Found           int     `json:"found"`
	FoundDetectable int     `json:"found_detectable"`
	Recall          float64 `json:"recall"` // over the detectable plants
	RecallLo        float64 `json:"recall_lo"`
	RecallHi        float64 `json:"recall_hi"`
	// Reported and TP count the distinct reports that sit on a plant or a lookalike of this
	// half; a report on neither (noise in a filler file) belongs to no half.
	Reported  int     `json:"reported"`
	TP        int     `json:"tp"`
	Precision float64 `json:"precision"`
}

// Marginal is what an engine alone contributes: the reports no other engine made. An engine
// with a high standalone precision and a low marginal one adds noise to the union.
type Marginal struct {
	Reported  int     `json:"reported"`
	TP        int     `json:"tp"`
	Precision float64 `json:"precision"`
	Found     int     `json:"found"` // plants only this engine found
}

// Overfit compares the pipeline on the two halves. A large positive gap means the rules were
// fitted to what the tune half shows.
type Overfit struct {
	RecallTune       float64 `json:"recall_tune"`
	RecallHeldOut    float64 `json:"recall_held_out"`
	PrecisionTune    float64 `json:"precision_tune"`
	PrecisionHeldOut float64 `json:"precision_held_out"`
	RecallGap        float64 `json:"recall_gap"`
	PrecisionGap     float64 `json:"precision_gap"`
}

// TypeScore is recall and precision for one provider type. A reported fingerprint belongs
// to the type of the plant it identifies, or to the engine's own type when it identifies
// nothing.
type TypeScore struct {
	Rate
	Reported  int     `json:"reported"`
	TP        int     `json:"tp"`
	Precision float64 `json:"precision"`
}

// FalsePositive is a reported fingerprint that identifies no positive plant. Only display
// forms appear here: the shape, never the value.
type FalsePositive struct {
	Class string `json:"class"` // "negative:<kind>" or "other"
	Plant string `json:"plant,omitempty"`
	Rule  string `json:"rule"`
	Type  string `json:"type"`
	Path  string `json:"path"`
	Line  int    `json:"line"`
	Shape string `json:"shape"`
}

// EngineResult is one engine's (or the union's, or the pipeline's) score.
type EngineResult struct {
	Name    string  `json:"name"`
	Version string  `json:"version,omitempty"`
	Skipped string  `json:"skipped,omitempty"` // why it did not run
	Error   string  `json:"error,omitempty"`
	Seconds float64 `json:"seconds"`

	Hits       int `json:"hits"`     // hits received
	Reported   int `json:"reported"` // distinct fingerprints among them
	TP         int `json:"tp"`
	FPNegative int `json:"fp_negative"` // lookalikes: placeholders, hashes, public-by-design values, invalid twins
	FPExtent   int `json:"fp_extent"`   // right file and line, a different extent of the credential
	FPOther    int `json:"fp_other"`    // noise
	// TPContained is how many of TP were credited by span containment (STEAL P0-24): a report on
	// the plant's own line that is long enough to cover min(len, 12) characters of it, whose
	// fingerprint is none the truth knows. The rest matched a fingerprint of the plant.
	TPContained int `json:"tp_contained,omitempty"`
	// TypeOK counts the TPs whose type is the plant's: the type is scored apart from the hit
	// (a secret found by a generic rule is found, and mistyped).
	TypeOK       int     `json:"type_ok,omitempty"`
	TypeTotal    int     `json:"type_total,omitempty"`
	TypeAccuracy float64 `json:"type_accuracy,omitempty"`

	Positives       int `json:"positives"`
	Found           int `json:"found"`
	Detectable      int `json:"detectable"`
	FoundDetectable int `json:"found_detectable"`
	// Own* score an engine only on plants its own rules cover as planted (the truth knows
	// betterleaks' and trufflehog's rules, not gitleaks' or titus'): a miss there is a bug,
	// not a gap in coverage.
	OwnDetectable int     `json:"own_detectable,omitempty"`
	OwnFound      int     `json:"own_found,omitempty"`
	RecallOwn     float64 `json:"recall_own,omitempty"`
	// Known* score plants whose value (or an encoding a known-secret matcher registers) sits
	// in the file as bytes: a matcher holding the raw value must find all of them.
	KnownTotal  int     `json:"known_total"`
	KnownFound  int     `json:"known_found"`
	RecallKnown float64 `json:"recall_known"`

	// Recall is over plants marked detectable by design (the acceptance number);
	// RecallAll is over every positive plant; Precision is TP over distinct reported
	// fingerprints.
	Recall    float64 `json:"recall"`
	RecallAll float64 `json:"recall_all"`
	Precision float64 `json:"precision"`
	// RecallLo and RecallHi are the 95% Wilson interval of Recall: with 300 detectable plants
	// the lower bound clears 98% only if at most one is missed.
	RecallLo float64 `json:"recall_lo"`
	RecallHi float64 `json:"recall_hi"`

	// FPPerMLine is false alerts per million lines of the corpus that hold no secret, and
	// PrecisionAt turns it and Recall into the precision to expect where a secret is one line
	// in a thousand, a hundred thousand or a million (keys "1e-3", "1e-5", "1e-6"). The corpus
	// is enriched, so its own precision is far above what these say (STEAL P0-25).
	FPPerMLine  float64            `json:"fp_per_mline,omitempty"`
	PrecisionAt map[string]float64 `json:"precision_at,omitempty"`

	ByType    map[string]*TypeScore `json:"by_type"`
	ByVariant map[string]*Rate      `json:"by_variant"`
	ByHalf    map[string]*HalfScore `json:"by_half,omitempty"`
	Marginal  *Marginal             `json:"marginal,omitempty"`

	// what the engine reported, for Marginal; not part of the result file
	keys    map[string]bool
	tpKeys  map[string]bool
	foundBy map[int]bool

	OwnMissed      []string        `json:"own_missed,omitempty"`          // plants its own rules cover that it did not report
	Missed         []string        `json:"missed,omitempty"`              // detectable plants not found
	MissedOther    []string        `json:"missed_undetectable,omitempty"` // non-detectable plants not found
	FalsePositives []FalsePositive `json:"false_positives,omitempty"`
	// NearMiss lists plants an engine flagged at the right file and line under a different
	// fingerprint: it saw the credential but reported a different extent of it.
	NearMiss []string `json:"near_miss,omitempty"`
}

// Results is results.json. Union is the regex engines together; the known matcher, when given,
// is scored on its own and joins them only in Pipeline, which is everything after triage.
type Results struct {
	Seed     uint64         `json:"seed"`
	Scale    int            `json:"scale"`
	Corpus   Stats          `json:"corpus"`
	Engines  []EngineResult `json:"engines"`
	Union    EngineResult   `json:"union"`
	Gaps     []Gap          `json:"gaps,omitempty"`
	Pipeline EngineResult   `json:"pipeline"`
	// Seconds the engines took one after another; ParallelSeconds is the slowest engine plus
	// triage, which is what the pipeline costs when engines run side by side.
	SequentialSeconds float64  `json:"sequential_seconds"`
	ParallelSeconds   float64  `json:"parallel_seconds"`
	Notes             []string `json:"notes,omitempty"`

	// Gate says whether the planted corpus is big and wide enough to prove a recall claim.
	Gate Gate `json:"gate"`
	// Overfit is the pipeline's recall and precision on the tune half against the held-out half.
	Overfit *Overfit `json:"overfit,omitempty"`
	// PipelineVerified is set when the pipeline row comes from a run with verification on; the
	// engine rows never do (raw precision is measured without it).
	PipelineVerified bool          `json:"pipeline_verified,omitempty"`
	Speed            []SpeedResult `json:"speed,omitempty"`

	heldOut map[string]bool // plant ids of the held-out half; Markdown does not list their misses
}

// Gap is a provider type some plants of which no engine reported although none was expected
// to: the bench's list of what rules/keyguard.toml, the known matcher or a new engine must cover.
type Gap struct {
	Type     string   `json:"type"`
	Plants   []string `json:"plants"`
	Variants []string `json:"variants"`
	Why      string   `json:"why"`
}

// ScoreOptions tunes Score.
type ScoreOptions struct {
	// Keep is the pipeline's triage: it returns false for a hit that should not alert. Nil
	// uses SimpleTriage; the real triage package plugs in here at integration.
	Keep func(core.Hit) bool
	// OutDir receives results.json and results.md. Empty means the corpus dir.
	OutDir string
	// EngineTimeout bounds each engine's scan; a hung engine is reported, not waited for.
	// Zero means ten minutes.
	EngineTimeout time.Duration
	// Rules is an extra rules file passed to the engines that take one (ScanOpts.Rules), so
	// a candidate rules/keyguard.toml can be scored against the gaps the bench lists.
	Rules string
	// Verify scores the pipeline from a second run of every engine with verification on, which
	// asks the providers' APIs about the corpus's fake keys. Engine rows are always raw, with
	// verification off (STEAL P0-24).
	Verify bool
	// SpeedRuns, when positive, times each engine that many times over the corpus, the first run
	// as cold and the rest as warm, and records wall, CPU and peak memory (5 in the research).
	SpeedRuns int
}

// Score runs every engine over the corpus repo, and the known matcher if given, and scores
// them against truth.json. Engines must fingerprint with Corpus.Key (bench.KeyringFor of the
// corpus seed) or no hit will match a plant. Results are also written as results.json and
// results.md into the corpus dir.
func Score(ctx context.Context, engines []core.Engine, known core.KnownMatcher, corpusDir string) (*Results, error) {
	return ScoreWith(ctx, engines, known, corpusDir, ScoreOptions{})
}

// ScoreWith is Score with options.
func ScoreWith(ctx context.Context, engines []core.Engine, known core.KnownMatcher, corpusDir string, so ScoreOptions) (*Results, error) {
	c, err := Load(corpusDir)
	if err != nil {
		return nil, err
	}
	ix := newIndex(c.Truth)
	keep := so.Keep
	if keep == nil {
		keep = SimpleTriage(c.Key)
	}
	res := &Results{Seed: c.Truth.Seed, Scale: c.Truth.Scale, Corpus: c.Truth.Stats, Gate: GateOf(c.Truth), heldOut: ix.heldOutIDs()}
	timeout := so.EngineTimeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}

	tmpl := core.Location{Source: "local:" + c.Repo, Kind: "repo", Visibility: core.Local}
	scan := func(e core.Engine, verify bool) ([]core.Hit, float64, error) {
		var mu sync.Mutex
		var hits []core.Hit
		ectx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		start := time.Now()
		err := e.ScanGit(ectx, c.Repo, core.Range{All: true}, core.ScanOpts{Loc: tmpl, Rules: so.Rules, Verify: verify}, func(h core.Hit) {
			mu.Lock()
			hits = append(hits, h)
			mu.Unlock()
		})
		return hits, time.Since(start).Seconds(), err
	}
	var scanned []core.Hit  // what the regex engines reported, verification off: the union
	var pipeline []core.Hit // what the pipeline starts from: the same, or a verified run of it
	var maxSec, engineSec float64
	for _, e := range engines {
		er := EngineResult{Name: e.Name(), Version: e.Version()}
		if !e.Available() {
			er.Skipped = "binary not available"
			res.Engines = append(res.Engines, ix.evaluate(er, nil))
			continue
		}
		hits, sec, err := scan(e, false)
		er.Seconds = sec
		if err != nil {
			er.Error = err.Error()
		}
		engineSec += sec
		scanned = append(scanned, hits...)
		pipe, pipeSec := hits, sec
		if so.Verify {
			var verr error
			if pipe, pipeSec, verr = scan(e, true); verr != nil {
				res.Notes = append(res.Notes, e.Name()+": the verified run failed: "+verr.Error())
			}
			res.PipelineVerified = true
		}
		maxSec = max(maxSec, pipeSec)
		pipeline = append(pipeline, pipe...)
		res.Engines = append(res.Engines, ix.evaluate(er, hits))
	}
	all := pipeline
	res.SequentialSeconds = engineSec
	if known != nil {
		er := EngineResult{Name: "known"}
		start := time.Now()
		hits, err := scanKnown(ctx, c.Repo, known, tmpl)
		er.Seconds = time.Since(start).Seconds()
		if err != nil {
			er.Error = err.Error()
		}
		res.SequentialSeconds += er.Seconds
		maxSec = max(maxSec, er.Seconds)
		all = append(append([]core.Hit{}, pipeline...), hits...)
		res.Engines = append(res.Engines, ix.evaluate(er, hits))
	}

	res.Union = ix.evaluate(EngineResult{Name: "union", Seconds: engineSec}, scanned)
	start := time.Now()
	kept := make([]core.Hit, 0, len(all))
	for _, h := range all {
		if keep(h) {
			kept = append(kept, h)
		}
	}
	triage := time.Since(start).Seconds()
	res.ParallelSeconds = maxSec + triage
	res.Pipeline = ix.evaluate(EngineResult{Name: "pipeline", Seconds: res.ParallelSeconds}, kept)
	res.Notes = append(res.Notes, ix.notes(res)...)
	res.Gaps = ix.gaps(res.Union)
	res.finish()

	if so.SpeedRuns > 0 {
		for _, e := range engines {
			if !e.Available() {
				continue
			}
			sr := MeasureSpeed(ctx, e.Name(), e.Version(), filepath.Base(c.Repo), so.SpeedRuns, func(ctx context.Context) error {
				ectx, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				return e.ScanGit(ectx, c.Repo, core.Range{All: true}, core.ScanOpts{Loc: tmpl, Rules: so.Rules}, func(core.Hit) {})
			})
			res.Speed = append(res.Speed, sr)
		}
	}

	out := so.OutDir
	if out == "" {
		out = corpusDir
	}
	if err := res.WriteTo(out); err != nil {
		return res, err
	}
	return res, nil
}

// finish derives what depends on more than one row: each engine's marginal contribution, the
// false-alert rate per line and the precision it implies where secrets are rare, and the gap
// between the two halves.
func (r *Results) finish() {
	lines := r.Corpus.Lines - r.Corpus.Positives // a plant is a line or a few; the rest are clean
	rows := make([]*EngineResult, 0, len(r.Engines)+2)
	for i := range r.Engines {
		rows = append(rows, &r.Engines[i])
	}
	rows = append(rows, &r.Union, &r.Pipeline)
	for _, e := range rows {
		if lines <= 0 || e.Skipped != "" {
			continue
		}
		fpLine := float64(e.FPNegative+e.FPExtent+e.FPOther) / float64(lines)
		e.FPPerMLine = fpLine * 1e6
		e.PrecisionAt = map[string]float64{}
		for _, prev := range Prevalences {
			e.PrecisionAt[prevalenceLabel(prev)] = PrecisionAt(prev, e.Recall, fpLine)
		}
	}
	for i := range r.Engines {
		r.Engines[i].Marginal = marginalOf(i, r.Engines)
	}
	t, h := r.Pipeline.ByHalf[HalfTune], r.Pipeline.ByHalf[HalfHeldOut]
	if t != nil && h != nil && t.Detectable > 0 && h.Detectable > 0 {
		r.Overfit = &Overfit{
			RecallTune: t.Recall, RecallHeldOut: h.Recall, PrecisionTune: t.Precision, PrecisionHeldOut: h.Precision,
			RecallGap: t.Recall - h.Recall, PrecisionGap: t.Precision - h.Precision,
		}
	}
}

func prevalenceLabel(p float64) string { return fmt.Sprintf("1e-%d", int(math.Round(-math.Log10(p)))) }

// marginalOf is what engine i reports that no other engine does.
func marginalOf(i int, rows []EngineResult) *Marginal {
	e := rows[i]
	if e.Skipped != "" {
		return nil
	}
	m := &Marginal{}
	for k := range e.keys {
		alone := true
		for j, o := range rows {
			if j != i && o.keys[k] {
				alone = false
				break
			}
		}
		if alone {
			m.Reported++
			if e.tpKeys[k] {
				m.TP++
			}
		}
	}
	for p := range e.foundBy {
		alone := true
		for j, o := range rows {
			if j != i && o.foundBy[p] {
				alone = false
				break
			}
		}
		if alone {
			m.Found++
		}
	}
	m.Precision = ratio(m.TP, m.Reported)
	return m
}

// WriteTo writes results.json and results.md into dir.
func (r *Results) WriteTo(dir string) error {
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "results.json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "results.md"), []byte(r.Markdown()), 0o644)
}

// ---- matching ----

// containSlack is how much longer than a plant a report may be and still be taken as covering
// it: the variable name and quotes an engine reports with the value, but not a whole minified line.
const containSlack = 120

// index answers "which plant does this fingerprint or location belong to".
type index struct {
	t      *Truth
	posFP  map[string]int   // fingerprint (primary or alternate) -> positive plant
	negFP  map[string]int   // same for negatives
	posLoc map[string][]int // path:line -> positive plants
	negLoc map[string]int   // path -> negative plant, for negatives that carry no value
	half   []string         // plant -> its half

	ownRules map[string]bool // engines whose rules the truth knows
}

func locKey(path string, line int) string {
	path, _, _ = strings.Cut(path, "!") // archive entries read "<zip>!<entry>"
	return fmt.Sprintf("%s:%d", path, line)
}

func newIndex(t *Truth) *index {
	ix := &index{t: t, posFP: map[string]int{}, negFP: map[string]int{}, posLoc: map[string][]int{}, negLoc: map[string]int{}, ownRules: map[string]bool{}}
	for i, p := range t.Plants {
		for _, e := range p.DetectableBy {
			ix.ownRules[e] = true
		}
		h := p.Half
		if h == "" {
			h = HalfOf(p)
		}
		ix.half = append(ix.half, h)
		fps := append([]string{p.FP}, p.AltFPs...)
		for _, f := range fps {
			if f == "" {
				continue
			}
			if p.Positive {
				ix.posFP[f] = i
			} else if _, dup := ix.negFP[f]; !dup {
				ix.negFP[f] = i
			}
		}
		if p.Positive {
			for l := p.Location.Line; l <= max(p.Location.Line, p.Location.EndLine); l++ {
				k := locKey(p.Location.Path, l)
				ix.posLoc[k] = append(ix.posLoc[k], i)
			}
		} else if p.FP == "" {
			ix.negLoc[p.Location.Path] = i
		}
	}
	return ix
}

func (ix *index) heldOutIDs() map[string]bool {
	out := map[string]bool{}
	for i, p := range ix.t.Plants {
		if ix.half[i] == HalfHeldOut {
			out[p.ID] = true
		}
	}
	return out
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// contained finds the plant a report covers without carrying its fingerprint (STEAL P0-24: a hit
// is a true positive when its span contains at least min(len, 12) characters of the secret).
// A fingerprint cannot say where in a line a report starts, so the test is the one a hit still
// lets us make: it sits on the plant's own line, alone there, and is long enough to cover that
// much of it without being the whole line. A line with two plants is scored by fingerprint only.
func (ix *index) contained(h core.Hit) (int, bool) {
	on := ix.posLoc[locKey(h.Loc.Path, h.Loc.Line)]
	if len(on) != 1 || h.Len == 0 {
		return 0, false
	}
	p := ix.t.Plants[on[0]]
	if p.Len == 0 || h.Len < min(p.Len, 12) || h.Len > p.Len+containSlack {
		return 0, false
	}
	return on[0], true
}

// evaluate scores a hit set. er carries the name and timing already.
func (ix *index) evaluate(er EngineResult, hits []core.Hit) EngineResult {
	er.Hits = len(hits)
	er.ByType = map[string]*TypeScore{}
	er.ByVariant = map[string]*Rate{}
	er.ByHalf = map[string]*HalfScore{HalfTune: {}, HalfHeldOut: {}}
	er.keys, er.tpKeys, er.foundBy = map[string]bool{}, map[string]bool{}, map[int]bool{}
	typeOf := func(t string) *TypeScore {
		if er.ByType[t] == nil {
			er.ByType[t] = &TypeScore{}
		}
		return er.ByType[t]
	}
	found := map[int]bool{}
	near := map[int]bool{}
	seen := map[string]bool{}
	// credit records a true positive on plant i
	credit := func(i int, h core.Hit, key string) {
		er.TP++
		found[i] = true
		er.tpKeys[key] = true
		ts := typeOf(ix.t.Plants[i].Type)
		ts.Reported++
		ts.TP++
		// the known matcher names the key it holds, not a provider type, so its hits say nothing
		// about whether a type was right
		if h.Type != "" && h.Engine != "known" {
			er.TypeTotal++
			if strings.EqualFold(h.Type, ix.t.Plants[i].Type) {
				er.TypeOK++
			}
		}
		hs := er.ByHalf[ix.half[i]]
		hs.Reported++
		hs.TP++
	}
	for _, h := range hits {
		key := h.FP
		if key == "" {
			key = "loc:" + h.Loc.Key()
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		er.keys[key] = true
		er.Reported++
		if i, ok := ix.posFP[h.FP]; ok && h.FP != "" {
			credit(i, h, key)
			continue
		}
		fpos := FalsePositive{Class: "other", Rule: h.Rule, Type: h.Type, Path: h.Loc.Path, Line: h.Loc.Line, Shape: h.Shape}
		onPlant := ix.posLoc[locKey(h.Loc.Path, h.Loc.Line)]
		if _, isNeg := ix.negFP[h.FP]; !isNeg || h.FP == "" {
			if i, ok := ix.contained(h); ok {
				er.TPContained++
				credit(i, h, key)
				continue
			}
		}
		switch i, ok := ix.negFP[h.FP]; {
		case ok && h.FP != "":
			p := ix.t.Plants[i]
			fpos.Class, fpos.Plant, fpos.Type = "negative:"+p.Kind, p.ID, p.Type
			er.FPNegative++
			er.ByHalf[ix.half[i]].Reported++
		case len(onPlant) > 0:
			// the right place, but not an extent of the credential the truth knows
			p := ix.t.Plants[onPlant[0]]
			fpos.Class, fpos.Plant, fpos.Type = "extent", p.ID, p.Type
			er.FPExtent++
			er.ByHalf[ix.half[onPlant[0]]].Reported++
		default:
			if j, ok := ix.negLoc[strings.SplitN(h.Loc.Path, "!", 2)[0]]; ok {
				p := ix.t.Plants[j]
				fpos.Class, fpos.Plant, fpos.Type = "negative:"+p.Kind, p.ID, p.Type
				er.FPNegative++
				er.ByHalf[ix.half[j]].Reported++
			} else {
				er.FPOther++
			}
		}
		if fpos.Type == "" {
			fpos.Type = "unknown"
		}
		typeOf(fpos.Type).Reported++
		for _, i := range onPlant {
			near[i] = true
		}
		er.FalsePositives = append(er.FalsePositives, fpos)
	}

	for i, p := range ix.t.Plants {
		if !p.Positive {
			continue
		}
		er.Positives++
		ts, vs, hs := typeOf(p.Type), er.ByVariant[p.Variant], er.ByHalf[ix.half[i]]
		if vs == nil {
			vs = &Rate{}
			er.ByVariant[p.Variant] = vs
		}
		for _, r := range []*Rate{&ts.Rate, vs} {
			r.Total++
			if found[i] {
				r.Found++
			}
			if p.Detectable {
				r.Detectable++
				if found[i] {
					r.FoundDetectable++
				}
			}
		}
		hs.Positives++
		if found[i] {
			er.Found++
			hs.Found++
			er.foundBy[i] = true
		}
		if p.Detectable {
			er.Detectable++
			hs.Detectable++
			if found[i] {
				er.FoundDetectable++
				hs.FoundDetectable++
			}
		}
		if p.Known {
			er.KnownTotal++
			if found[i] {
				er.KnownFound++
			}
		}
		if ix.ownRules[er.Name] && slices.Contains(p.DetectableBy, er.Name) {
			er.OwnDetectable++
			if found[i] {
				er.OwnFound++
			} else {
				er.OwnMissed = append(er.OwnMissed, p.ID)
			}
		}
		if !found[i] {
			if p.Detectable {
				er.Missed = append(er.Missed, p.ID)
			} else {
				er.MissedOther = append(er.MissedOther, p.ID)
			}
			if near[i] {
				er.NearMiss = append(er.NearMiss, p.ID)
			}
		}
	}
	er.Recall = ratio(er.FoundDetectable, er.Detectable)
	er.RecallLo, er.RecallHi = Wilson(er.FoundDetectable, er.Detectable)
	er.RecallOwn = ratio(er.OwnFound, er.OwnDetectable)
	er.RecallKnown = ratio(er.KnownFound, er.KnownTotal)
	er.RecallAll = ratio(er.Found, er.Positives)
	er.Precision = ratio(er.TP, er.Reported)
	er.TypeAccuracy = ratio(er.TypeOK, er.TypeTotal)
	for _, ts := range er.ByType {
		ts.finish()
		ts.Precision = ratio(ts.TP, ts.Reported)
	}
	for _, rs := range er.ByVariant {
		rs.finish()
	}
	for _, hs := range er.ByHalf {
		hs.Recall = ratio(hs.FoundDetectable, hs.Detectable)
		hs.RecallLo, hs.RecallHi = Wilson(hs.FoundDetectable, hs.Detectable)
		hs.Precision = ratio(hs.TP, hs.Reported)
	}
	sort.Strings(er.Missed)
	sort.Strings(er.OwnMissed)
	sort.Strings(er.MissedOther)
	sort.Strings(er.NearMiss)
	sort.Slice(er.FalsePositives, func(i, j int) bool {
		a, b := er.FalsePositives[i], er.FalsePositives[j]
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	return er
}

// gaps groups the plants the union missed and was not expected to find by provider type.
func (ix *index) gaps(union EngineResult) []Gap {
	byID := map[string]Plant{}
	for _, p := range ix.t.Plants {
		byID[p.ID] = p
	}
	groups := map[string]*Gap{}
	for _, id := range union.MissedOther {
		p := byID[id]
		g := groups[p.Type]
		if g == nil {
			g = &Gap{Type: p.Type}
			groups[p.Type] = g
		}
		g.Plants = append(g.Plants, id)
		if !slices.Contains(g.Variants, p.Variant) {
			g.Variants = append(g.Variants, p.Variant)
		}
		if _, why, ok := strings.Cut(p.Note, "undetected by design: "); ok && !strings.Contains(g.Why, why) {
			if g.Why != "" {
				g.Why += "; "
			}
			g.Why += why
		}
	}
	out := make([]Gap, 0, len(groups))
	for _, g := range groups {
		sort.Strings(g.Variants)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// notes flags setups that make a score meaningless rather than bad.
func (ix *index) notes(r *Results) []string {
	var out []string
	for _, e := range r.Engines {
		if e.Skipped != "" || e.Error != "" {
			continue
		}
		if e.Hits > 0 && e.TP == 0 && e.FPNegative == 0 && len(e.NearMiss) > 0 {
			out = append(out, fmt.Sprintf("%s: %d hits, none matching a fingerprint, yet %d land on plant lines: the engine probably fingerprints with a different keyring than Corpus.Key", e.Name, e.Hits, len(e.NearMiss)))
		}
		if e.Hits == 0 {
			out = append(out, e.Name+": no hits at all; check the engine ran over the repo")
		}
	}
	return out
}
