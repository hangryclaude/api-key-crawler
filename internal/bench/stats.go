package bench

import (
	"math"
	"sort"

	"keyguard/internal/core"
)

// z95 is the two-sided 95% quantile of the normal distribution.
const z95 = 1.959963984540054

// Wilson is the 95% Wilson score interval for k successes in n trials. It stays inside [0, 1]
// and behaves at k == n, where the textbook normal interval collapses to a point: that is why
// every "recall of a few hundred plants" figure here carries one (STEAL P0-25).
func Wilson(k, n int) (lo, hi float64) { return wilsonF(float64(k), float64(n)) }

func wilsonF(k, n float64) (lo, hi float64) {
	if n <= 0 {
		return 0, 1
	}
	p := k / n
	z2 := z95 * z95
	den := 1 + z2/n
	mid := (p + z2/(2*n)) / den
	half := z95 * math.Sqrt(p*(1-p)/n+z2/(4*n*n)) / den
	lo, hi = max(0, mid-half), min(1, mid+half)
	// at the ends the bound is exact, and rounding must not leave the point estimate outside it
	if k >= n {
		hi = 1
	}
	if k <= 0 {
		lo = 0
	}
	return lo, hi
}

// RuleOfThree is the 95% upper bound on an event rate after seeing no event in n trials:
// 3/n. It is what an estimate of "false positives per alert" can honestly say when a sample
// of n alerts held none.
func RuleOfThree(n int) float64 {
	if n <= 0 {
		return 1
	}
	return min(1, 3/float64(n))
}

// MinPlantsForRecall is the smallest number of detectable plants that proves recall of at
// least target, at 95% confidence, when `misses` of them are missed: the Wilson lower bound of
// (n-misses)/n first reaches target. For 98% it is 189 with no miss and a little under 300
// with one, which is why the gate asks for 300 plants (docs/STEAL.md P0-25). It returns 0 when
// no number up to a million suffices.
func MinPlantsForRecall(target float64, misses int) int {
	for n := misses + 1; n <= 1_000_000; n++ {
		if lo, _ := Wilson(n-misses, n); lo >= target {
			return n
		}
	}
	return 0
}

// PrecisionAt is the precision a scanner would have where secrets are rare. recall is the
// share of secrets it finds; fpPerLine is the false alerts it raises per line that holds no
// secret, measured on natural code; prevalence is secrets per line. At one secret in 100,000
// lines even a scanner that raises 2 false alerts per 10,000 lines is right about once in six
// (STEAL P0-25: CredData has 4,583 credentials in 19.5 million lines).
func PrecisionAt(prevalence, recall, fpPerLine float64) float64 {
	tp := prevalence * recall
	fp := (1 - prevalence) * fpPerLine
	if tp+fp == 0 {
		return 0
	}
	return tp / (tp + fp)
}

// Prevalences are the secrets-per-line figures the report converts precision to.
var Prevalences = []float64{1e-3, 1e-5, 1e-6}

// Stratum is one stratum of an alert sample: how many alerts there were, how many were drawn
// and judged, and how many of those were real.
type Stratum struct {
	Name       string `json:"name"`
	Population int    `json:"population"`
	Sampled    int    `json:"sampled"`
	TP         int    `json:"tp"`
}

// Estimate is a precision estimated from a stratified sample.
type Estimate struct {
	Precision float64 `json:"precision"`
	Lo        float64 `json:"lo"`
	Hi        float64 `json:"hi"`
	Sampled   int     `json:"sampled"`
	// Census is set when every alert was judged, so the figure is exact.
	Census bool `json:"census,omitempty"`
	// ZeroFP is set when the sample held no false alert. Lo is then the rule of three, 1 - 3/n,
	// not a Wilson bound: with nothing to count, 3/n is what n alerts can rule out.
	ZeroFP bool `json:"zero_fp,omitempty"`
}

// Stratified estimates precision from a sample drawn per stratum. The point estimate weights
// each stratum by its share of the alerts, so a stratum sampled lightly is not over-trusted;
// the interval is Wilson's, at the effective sample size that weighting leaves (Kish). Strata
// with nothing sampled are ignored and say so through Sampled.
func Stratified(strata []Stratum) Estimate {
	var pop, sampled, tp int
	for _, s := range strata {
		if s.Sampled > 0 {
			pop += s.Population
			sampled += s.Sampled
			tp += s.TP
		}
	}
	if sampled == 0 || pop == 0 {
		return Estimate{Lo: 0, Hi: 1}
	}
	var p, variance float64
	census := true
	for _, s := range strata {
		if s.Sampled == 0 {
			continue
		}
		w := float64(s.Population) / float64(pop)
		ph := float64(s.TP) / float64(s.Sampled)
		p += w * ph
		if s.Sampled < s.Population {
			census = false
			// finite-population correction: a stratum judged in full adds no variance
			variance += w * w * ph * (1 - ph) / float64(s.Sampled) * (1 - float64(s.Sampled)/float64(s.Population))
		}
	}
	est := Estimate{Precision: p, Sampled: sampled, Census: census}
	switch {
	case census:
		est.Lo, est.Hi = p, p
	case tp == sampled:
		est.ZeroFP = true
		est.Lo, est.Hi = 1-RuleOfThree(sampled), 1
	default:
		n := float64(sampled)
		if variance > 0 {
			n = p * (1 - p) / variance
		}
		est.Lo, est.Hi = wilsonF(p*n, n)
	}
	return est
}

// SampleAlerts draws up to per alerts from each stratum, by type, in a repeatable order, and
// returns them with the strata filled in for Stratified once someone has judged the sample.
// The same hits and seed give the same sample.
func SampleAlerts(hits []core.Hit, per int, seed uint64) ([]core.Hit, []Stratum) {
	by := map[string][]core.Hit{}
	for _, h := range hits {
		t := h.Type
		if t == "" {
			t = "unknown"
		}
		by[t] = append(by[t], h)
	}
	names := make([]string, 0, len(by))
	for t := range by {
		names = append(names, t)
	}
	sort.Strings(names)
	r := newRand(seed, "alert-sample")
	var sample []core.Hit
	var strata []Stratum
	for _, t := range names {
		hs := by[t]
		// order by fingerprint so the draw does not depend on the engines' output order
		sort.Slice(hs, func(i, j int) bool {
			if hs[i].FP != hs[j].FP {
				return hs[i].FP < hs[j].FP
			}
			return hs[i].Loc.Key() < hs[j].Loc.Key()
		})
		r.Shuffle(len(hs), func(i, j int) { hs[i], hs[j] = hs[j], hs[i] })
		n := min(per, len(hs))
		sample = append(sample, hs[:n]...)
		strata = append(strata, Stratum{Name: t, Population: len(hs), Sampled: n})
	}
	return sample, strata
}

// Judge fills the TP count of each stratum from a verdict on every sampled alert.
func Judge(sample []core.Hit, strata []Stratum, real func(core.Hit) bool) []Stratum {
	out := append([]Stratum(nil), strata...)
	idx := map[string]int{}
	for i, s := range out {
		idx[s.Name] = i
	}
	for _, h := range sample {
		t := h.Type
		if t == "" {
			t = "unknown"
		}
		if real(h) {
			out[idx[t]].TP++
		}
	}
	return out
}
