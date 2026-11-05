package bench

import (
	"math"
	"testing"

	"keyguard/internal/core"
)

func within(a, b, eps float64) bool { return math.Abs(a-b) <= eps }

// The reference figures were computed apart from this code, in Python, from the Wilson formula.
func TestWilsonMatchesReferenceValues(t *testing.T) {
	for _, tc := range []struct {
		k, n   int
		lo, hi float64
	}{
		{0, 10, 0, 0.277533},
		{10, 10, 0.722467, 1},
		{50, 100, 0.403832, 0.596168},
		{81, 100, 0.722212, 0.874852},
		{299, 300, 0.981363, 0.999411},
		{298, 300, 0.976022, 0.998170},
		{0, 1, 0, 0.793451},
	} {
		lo, hi := Wilson(tc.k, tc.n)
		if !within(lo, tc.lo, 1e-6) || !within(hi, tc.hi, 1e-6) {
			t.Errorf("Wilson(%d,%d) = %.6f %.6f, want %.6f %.6f", tc.k, tc.n, lo, hi, tc.lo, tc.hi)
		}
	}
	if lo, hi := Wilson(0, 0); lo != 0 || hi != 1 {
		t.Errorf("no trials should say nothing: %v %v", lo, hi)
	}
}

// 189 plants with no miss prove 98% recall at 95% confidence; one miss needs 280 (STEAL
// P0-25 rounds it to "about 290"). The gate of 300 therefore tolerates exactly one miss.
func TestMinPlantsForRecall(t *testing.T) {
	for _, tc := range []struct {
		target float64
		misses int
		want   int
	}{{0.98, 0, 189}, {0.98, 1, 280}, {0.98, 2, 361}, {0.95, 0, 73}} {
		if got := MinPlantsForRecall(tc.target, tc.misses); got != tc.want {
			t.Errorf("MinPlantsForRecall(%v, %d) = %d, want %d", tc.target, tc.misses, got, tc.want)
		}
	}
	if lo, _ := Wilson(299, 300); lo < 0.98 {
		t.Error("300 plants with one miss should still prove 98%")
	}
	if lo, _ := Wilson(298, 300); lo >= 0.98 {
		t.Error("300 plants with two misses should not prove 98%")
	}
}

func TestPrecisionAtPrevalence(t *testing.T) {
	// 98% recall, 2 false alerts per 10,000 clean lines
	for prev, want := range map[float64]float64{1e-3: 0.830649, 1e-5: 0.046712, 1e-6: 0.004876} {
		if got := PrecisionAt(prev, 0.98, 2e-4); !within(got, want, 1e-6) {
			t.Errorf("precision at %g = %.6f, want %.6f", prev, got, want)
		}
	}
	if PrecisionAt(1e-5, 0.9, 0) != 1 {
		t.Error("a scanner with no false alerts is always right")
	}
	if PrecisionAt(1e-5, 0, 0) != 0 {
		t.Error("nothing found and nothing wrong must not divide by zero")
	}
	// a worse scanner is never more precise at any prevalence
	for _, prev := range Prevalences {
		if PrecisionAt(prev, 0.98, 4e-4) >= PrecisionAt(prev, 0.98, 2e-4) {
			t.Errorf("doubling the false alert rate did not lower precision at %g", prev)
		}
	}
}

func TestRuleOfThree(t *testing.T) {
	if got := RuleOfThree(60); !within(got, 0.05, 1e-12) {
		t.Errorf("RuleOfThree(60) = %v", got)
	}
	if RuleOfThree(0) != 1 || RuleOfThree(2) != 1 {
		t.Error("with fewer than 3 trials the bound is vacuous (1)")
	}
}

func TestStratifiedEstimate(t *testing.T) {
	// two strata: 100 alerts of which 10 judged (9 real), 300 of which 20 judged (all real)
	e := Stratified([]Stratum{{"a", 100, 10, 9}, {"b", 300, 20, 20}})
	if !within(e.Precision, 0.975, 1e-9) || e.Census || e.ZeroFP || e.Sampled != 30 {
		t.Fatalf("estimate %+v", e)
	}
	// reference: effective n 48.1481, Wilson (0.884831, 0.994974), computed apart from this code
	if !within(e.Lo, 0.884831, 1e-5) || !within(e.Hi, 0.994974, 1e-5) {
		t.Errorf("interval %.6f %.6f", e.Lo, e.Hi)
	}

	// no false alert in the sample: the rule of three speaks, not Wilson
	z := Stratified([]Stratum{{"a", 500, 60, 60}})
	if !z.ZeroFP || z.Precision != 1 || !within(z.Lo, 0.95, 1e-12) || z.Hi != 1 {
		t.Errorf("zero-FP sample: %+v", z)
	}

	// a stratum judged in full is exact and adds no uncertainty
	c := Stratified([]Stratum{{"a", 12, 12, 11}})
	if !c.Census || !within(c.Precision, 11.0/12, 1e-12) || c.Lo != c.Hi {
		t.Errorf("census: %+v", c)
	}

	// nothing sampled says nothing
	if n := Stratified([]Stratum{{"a", 10, 0, 0}}); n.Lo != 0 || n.Hi != 1 || n.Sampled != 0 {
		t.Errorf("empty sample: %+v", n)
	}
}

// A lightly sampled stratum must not drag the estimate: weights follow the alert counts, not
// the sample sizes.
func TestStratifiedWeightsByPopulation(t *testing.T) {
	// 1000 alerts of type a, all fine in a sample of 10; 10 alerts of type b, all wrong in 10
	e := Stratified([]Stratum{{"a", 1000, 10, 10}, {"b", 10, 10, 0}})
	want := 1000.0 / 1010
	if !within(e.Precision, want, 1e-12) {
		t.Errorf("precision %.6f, want the population-weighted %.6f (a pooled sample would say 0.5)", e.Precision, want)
	}
}

func TestSampleAlertsIsRepeatableAndStratified(t *testing.T) {
	var hits []core.Hit
	for i := 0; i < 50; i++ {
		hits = append(hits, core.Hit{FP: "fp-a-" + string(rune('A'+i%26)) + string(rune('a'+i/26)), Type: "alpha"})
	}
	for i := 0; i < 5; i++ {
		hits = append(hits, core.Hit{FP: "fp-b-" + string(rune('A'+i)), Type: "beta"})
	}
	a, sa := SampleAlerts(hits, 8, 7)
	b, sb := SampleAlerts(append([]core.Hit(nil), hits...), 8, 7)
	if len(a) != 8+5 || len(sa) != 2 {
		t.Fatalf("drew %d from %d strata, want 13 from 2", len(a), len(sa))
	}
	for i := range a {
		if a[i].FP != b[i].FP {
			t.Fatal("the same hits and seed gave different samples")
		}
	}
	if sa[0] != (Stratum{"alpha", 50, 8, 0}) || sa[1] != (Stratum{"beta", 5, 5, 0}) || sb[0] != sa[0] {
		t.Errorf("strata %+v", sa)
	}
	c, _ := SampleAlerts(hits, 8, 8)
	same := true
	for i := range c {
		same = same && c[i].FP == a[i].FP
	}
	if same {
		t.Error("another seed drew the identical sample")
	}
	// reversing the engines' output order must not change the draw
	rev := make([]core.Hit, len(hits))
	for i := range hits {
		rev[len(hits)-1-i] = hits[i]
	}
	d, _ := SampleAlerts(rev, 8, 7)
	for i := range d {
		if d[i].FP != a[i].FP {
			t.Fatal("the sample depends on the order the hits arrived in")
		}
	}

	judged := Judge(a, sa, func(h core.Hit) bool { return h.Type == "beta" })
	if judged[0].TP != 0 || judged[1].TP != 5 || sa[1].TP != 0 {
		t.Errorf("judged %+v (the input must not change: %+v)", judged, sa)
	}
}
