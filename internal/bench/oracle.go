package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

// Corpus B (STEAL P0-23) is the oracle: the known-secret matcher, which holds the hashes of the
// keys the user owns and has no false positives, run over every object of the mirrors. What it
// finds is a set of real leaks of their own keys, with no label anyone had to write. Each regex
// engine is then scored on how many of them it reports, and every secret that none of them
// reports is a rule waiting to be written, or a place the known matcher is the only net.

// OracleMirror is a repository the oracle reads. A bare mirror from ~/.keyguard/cache/mirrors
// is the usual one; any git repo works.
type OracleMirror struct {
	Name string // owner/name or any label; the frozen split cuts on it
	Dir  string
}

// OracleOptions tunes ScoreOracle.
type OracleOptions struct {
	Rules         string        // extra rules file for the engines that take one
	EngineTimeout time.Duration // per engine and mirror; zero means ten minutes
	// SpeedRuns, when positive, times every engine on every mirror that many times (cold first,
	// then warm): the per-repo timings P0-24 asks for, on the repos that matter.
	SpeedRuns int
}

// OracleSecret is one leaked secret, in display form: nothing here is a value.
type OracleSecret struct {
	ID    string `json:"id"`    // "kg" + 6 hex of the fingerprint
	Name  string `json:"name"`  // what the matcher knows the key as, such as OPENAI_API_KEY
	Shape string `json:"shape"` // prefix and last characters only
	Len   int    `json:"len"`
	Half  string `json:"half"`
	// Mirrors lists where it was found, and Where the first place, as path:line.
	Mirrors  []string `json:"mirrors"`
	Where    string   `json:"where,omitempty"`
	MissedBy []string `json:"missed_by,omitempty"`
}

// OracleHalf is an engine's recall on one half of the mirrors.
type OracleHalf struct {
	Secrets  int     `json:"secrets"`
	Found    int     `json:"found"`
	Recall   float64 `json:"recall"`
	RecallLo float64 `json:"recall_lo"`
	RecallHi float64 `json:"recall_hi"`
}

// OracleEngine is one engine's recall against the oracle.
type OracleEngine struct {
	Name    string  `json:"name"`
	Version string  `json:"version,omitempty"`
	Skipped string  `json:"skipped,omitempty"`
	Error   string  `json:"error,omitempty"`
	Seconds float64 `json:"seconds"`
	Secrets int     `json:"secrets"`
	Found   int     `json:"found"`
	// Contained is how many of Found were credited by span (a report on the secret's line of
	// the right length) and not by fingerprint.
	Contained int                    `json:"contained,omitempty"`
	Recall    float64                `json:"recall"`
	RecallLo  float64                `json:"recall_lo"`
	RecallHi  float64                `json:"recall_hi"`
	ByHalf    map[string]*OracleHalf `json:"by_half"`
}

// RuleCandidate is a group of oracle secrets no engine reported that look alike: the same
// name, the same visible prefix, the same length. It is what a new rule has to cover.
type RuleCandidate struct {
	Name  string   `json:"name"`
	Shape string   `json:"shape"`
	Len   int      `json:"len"`
	Seen  int      `json:"seen"`
	Where []string `json:"where"`
}

// OracleResult is the score of the engines on corpus B.
type OracleResult struct {
	Mirrors int            `json:"mirrors"`
	Secrets int            `json:"secrets"` // distinct oracle secrets, whichever mirror
	Engines []OracleEngine `json:"engines"`
	Union   OracleEngine   `json:"union"` // the regex engines together
	// Misses are the secrets no engine reported, in the tune half, and Candidates group them
	// into rules to write. The held-out half's misses are counted and never listed: they are the
	// score the rules are judged on.
	Misses        []OracleSecret  `json:"misses,omitempty"`
	Candidates    []RuleCandidate `json:"rule_candidates,omitempty"`
	HeldOutMisses int             `json:"held_out_misses"`
	Speed         []SpeedResult   `json:"speed,omitempty"`
	Notes         []string        `json:"notes,omitempty"`
}

type oracleLoc struct {
	mirror string
	key    string // locKey of the first place
}

type oracleUnit struct {
	fp    string
	half  string
	sec   OracleSecret
	locs  []oracleLoc
	found map[string]bool // engine -> found
}

// ScoreOracle runs the known matcher over every mirror to find the real leaks, runs each engine
// over the same mirrors and scores it against them. The unit is a distinct fingerprint within a
// half; an engine finds it when it reports the fingerprint, or reports a span of the right length on
// a line where the matcher found it. Engines must fingerprint with the keyring the matcher uses.
func ScoreOracle(ctx context.Context, engines []core.Engine, known core.KnownMatcher, mirrors []OracleMirror, o OracleOptions) (*OracleResult, error) {
	if known == nil {
		return nil, fmt.Errorf("bench: the oracle needs a known-secret matcher")
	}
	timeout := o.EngineTimeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	res := &OracleResult{Mirrors: len(mirrors)}
	units := map[string]*oracleUnit{} // half/fp
	for _, m := range mirrors {
		tmpl := core.Location{Source: "oracle:" + m.Name, Kind: "repo", Visibility: core.Local}
		hits, err := scanKnown(ctx, m.Dir, known, tmpl)
		if err != nil {
			return nil, fmt.Errorf("bench: oracle scan of %s: %w", m.Name, err)
		}
		half := Half(m.Name)
		for _, h := range hits {
			k := half + "/" + h.FP
			u := units[k]
			if u == nil {
				name := h.Known
				if _, n, ok := strings.Cut(h.Known, " "); ok {
					name = n
				}
				u = &oracleUnit{fp: h.FP, half: half, found: map[string]bool{}, sec: OracleSecret{
					ID: fp.ID(h.FP), Name: name, Shape: h.Shape, Len: h.Len, Half: half,
				}}
				units[k] = u
				if h.Loc.Path != "" {
					u.sec.Where = fmt.Sprintf("%s:%d", strings.SplitN(h.Loc.Path, "!", 2)[0], h.Loc.Line)
				}
			}
			if !slices.Contains(u.sec.Mirrors, m.Name) {
				u.sec.Mirrors = append(u.sec.Mirrors, m.Name)
			}
			u.locs = append(u.locs, oracleLoc{m.Name, locKey(h.Loc.Path, h.Loc.Line)})
		}
	}
	distinct := map[string]bool{}
	for _, u := range units {
		distinct[u.fp] = true
	}
	res.Secrets = len(distinct)

	var union []OracleEngine
	for _, e := range engines {
		oe := OracleEngine{Name: e.Name(), Version: e.Version(), ByHalf: map[string]*OracleHalf{HalfTune: {}, HalfHeldOut: {}}}
		if !e.Available() {
			oe.Skipped = "binary not available"
			res.Engines = append(res.Engines, oe)
			continue
		}
		byFP := map[string]map[string]bool{}   // mirror -> fingerprints reported
		byLoc := map[string]map[string][]int{} // mirror -> locKey -> lengths of the reports there
		for _, m := range mirrors {
			byFP[m.Name], byLoc[m.Name] = map[string]bool{}, map[string][]int{}
			var mu sync.Mutex
			ectx, cancel := context.WithTimeout(ctx, timeout)
			start := time.Now()
			err := e.ScanGit(ectx, m.Dir, core.Range{All: true}, core.ScanOpts{
				Loc:   core.Location{Source: "oracle:" + m.Name, Kind: "repo", Visibility: core.Local},
				Rules: o.Rules,
			}, func(h core.Hit) {
				mu.Lock()
				byFP[m.Name][h.FP] = true
				k := locKey(h.Loc.Path, h.Loc.Line)
				byLoc[m.Name][k] = append(byLoc[m.Name][k], h.Len)
				mu.Unlock()
			})
			cancel()
			oe.Seconds += time.Since(start).Seconds()
			if err != nil && oe.Error == "" {
				oe.Error = fmt.Sprintf("%s: %v", m.Name, err)
			}
		}
		for _, u := range units {
			byFPHit, byLocHit := false, false
			for _, l := range u.locs {
				if byFP[l.mirror][u.fp] {
					byFPHit = true
					break
				}
				for _, n := range byLoc[l.mirror][l.key] {
					if u.sec.Len > 0 && n >= min(u.sec.Len, 12) && n <= u.sec.Len+containSlack {
						byLocHit = true
					}
				}
			}
			if byFPHit || byLocHit {
				u.found[e.Name()] = true
				oe.ByHalf[u.half].Found++
				if !byFPHit {
					oe.Contained++
				}
			}
			oe.ByHalf[u.half].Secrets++
		}
		finishOracleEngine(&oe)
		res.Engines = append(res.Engines, oe)
		union = append(union, oe)

		if o.SpeedRuns > 0 {
			for _, m := range mirrors {
				res.Speed = append(res.Speed, MeasureSpeed(ctx, e.Name(), e.Version(), m.Name, o.SpeedRuns, func(ctx context.Context) error {
					ectx, cancel := context.WithTimeout(ctx, timeout)
					defer cancel()
					return e.ScanGit(ectx, m.Dir, core.Range{All: true}, core.ScanOpts{Loc: core.Location{Source: "oracle:" + m.Name, Kind: "repo", Visibility: core.Local}, Rules: o.Rules}, func(core.Hit) {})
				}))
			}
		}
	}

	// the union of the engines that ran, and the secrets none of them found
	res.Union = OracleEngine{Name: "union", ByHalf: map[string]*OracleHalf{HalfTune: {}, HalfHeldOut: {}}}
	var keys []string
	for k := range units {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		u := units[k]
		res.Union.ByHalf[u.half].Secrets++
		any := false
		for _, e := range union {
			if u.found[e.Name] {
				any = true
			} else {
				u.sec.MissedBy = append(u.sec.MissedBy, e.Name)
			}
		}
		if any {
			res.Union.ByHalf[u.half].Found++
			continue
		}
		if len(union) == 0 {
			continue
		}
		if u.half == HalfHeldOut {
			res.HeldOutMisses++
		} else {
			sort.Strings(u.sec.Mirrors)
			res.Misses = append(res.Misses, u.sec)
		}
	}
	for _, h := range res.Union.ByHalf {
		res.Union.Secrets += h.Secrets
		res.Union.Found += h.Found
	}
	finishOracleEngine(&res.Union)
	res.Candidates = ruleCandidates(res.Misses)
	if len(union) == 0 {
		res.Notes = append(res.Notes, "no regex engine ran, so every secret counts as unscored")
	}
	return res, nil
}

func finishOracleEngine(oe *OracleEngine) {
	oe.Secrets, oe.Found = 0, 0
	for _, h := range oe.ByHalf {
		h.Recall = ratio(h.Found, h.Secrets)
		h.RecallLo, h.RecallHi = Wilson(h.Found, h.Secrets)
		oe.Secrets += h.Secrets
		oe.Found += h.Found
	}
	oe.Recall = ratio(oe.Found, oe.Secrets)
	oe.RecallLo, oe.RecallHi = Wilson(oe.Found, oe.Secrets)
}

// ruleCandidates groups missed secrets that share a name, a visible prefix and a length.
func ruleCandidates(misses []OracleSecret) []RuleCandidate {
	type key struct {
		name, prefix string
		n            int
	}
	groups := map[key]*RuleCandidate{}
	var order []key
	for _, m := range misses {
		prefix, _, _ := strings.Cut(m.Shape, "…")
		k := key{m.Name, prefix, m.Len}
		g := groups[k]
		if g == nil {
			g = &RuleCandidate{Name: m.Name, Shape: prefix + "…", Len: m.Len}
			groups[k] = g
			order = append(order, k)
		}
		g.Seen++
		if len(g.Where) < 3 && m.Where != "" {
			g.Where = append(g.Where, m.Where)
		}
	}
	out := make([]RuleCandidate, 0, len(order))
	for _, k := range order {
		out = append(out, *groups[k])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seen != out[j].Seen {
			return out[i].Seen > out[j].Seen
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// WriteTo writes oracle.json and oracle.md into dir.
func (r *OracleResult) WriteTo(dir string) error {
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "oracle.json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "oracle.md"), []byte(r.Markdown()), 0o644)
}

// Markdown renders the oracle score. It names secrets by id, name and shape, never by value.
func (r *OracleResult) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# keyguard bench: the oracle\n\n%d mirrors; the known matcher found %d distinct leaked secrets in them.\n\n", r.Mirrors, r.Secrets)
	b.WriteString("| engine | version | seconds | secrets | found | recall | 95% Wilson | tune | held-out | by span |\n|---|---|--:|--:|--:|--:|--|--|--|--:|\n")
	rows := append(append([]OracleEngine{}, r.Engines...), r.Union)
	for _, e := range rows {
		if e.Skipped != "" {
			fmt.Fprintf(&b, "| %s | %s | skipped: %s |||||||\n", e.Name, e.Version, e.Skipped)
			continue
		}
		t, h := e.ByHalf[HalfTune], e.ByHalf[HalfHeldOut]
		fmt.Fprintf(&b, "| %s | %s | %.2f | %d | %d | %s | %s to %s | %s (%d/%d) | %s (%d/%d) | %d |\n", e.Name, e.Version, e.Seconds, e.Secrets, e.Found,
			pct(e.Recall), pct(e.RecallLo), pct(e.RecallHi), pct(t.Recall), t.Found, t.Secrets, pct(h.Recall), h.Found, h.Secrets, e.Contained)
	}
	fmt.Fprintf(&b, "\n## Missed by every engine\n\n%d in the tune half, listed; %d in the held-out half, counted and not listed.\n\n", len(r.Misses), r.HeldOutMisses)
	if len(r.Misses) > 0 {
		b.WriteString("| id | name | shape | length | first seen | mirrors |\n|---|---|---|--:|---|--:|\n")
		for i, m := range r.Misses {
			if i == 60 {
				fmt.Fprintf(&b, "| … %d more ||||||\n", len(r.Misses)-60)
				break
			}
			fmt.Fprintf(&b, "| %s | %s | `%s` | %d | %s | %d |\n", m.ID, m.Name, m.Shape, m.Len, m.Where, len(m.Mirrors))
		}
	}
	if len(r.Candidates) > 0 {
		b.WriteString("\n## Rules to write\n\nOne row per name, visible prefix and length among the misses.\n\n| name | prefix | length | secrets | where |\n|---|---|--:|--:|---|\n")
		for _, c := range r.Candidates {
			fmt.Fprintf(&b, "| %s | `%s` | %d | %d | %s |\n", c.Name, c.Shape, c.Len, c.Seen, strings.Join(c.Where, ", "))
		}
	}
	if len(r.Speed) > 0 {
		b.WriteString("\n## Speed per mirror\n\n| engine | mirror | runs | cold s | warm s | CPU s | peak RSS MB |\n|---|---|--:|--:|--:|--:|--:|\n")
		for _, sp := range r.Speed {
			fmt.Fprintf(&b, "| %s | %s | %d | %.2f | %.2f | %.2f | %.0f |\n", sp.Engine, sp.Repo, sp.Runs, sp.ColdSeconds, sp.WarmSeconds, sp.CPUSeconds, sp.PeakRSSMB)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "\n> %s\n", n)
	}
	return b.String()
}
