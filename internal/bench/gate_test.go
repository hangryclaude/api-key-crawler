package bench

import (
	"fmt"
	"slices"
	"testing"
)

// synthTruth is a truth with n detectable plants in f formats, each format in p placements.
func synthTruth(n, f, p int) *Truth {
	t := &Truth{}
	for i := 0; i < n; i++ {
		fmtID := fmt.Sprintf("fmt%02d", i%f)
		t.Plants = append(t.Plants, Plant{ID: fmt.Sprintf("p%d", i), Format: fmtID, Positive: true, Detectable: true,
			Variant: fmt.Sprintf("v%d", (i/f)%p)})
	}
	return t
}

func TestGateArithmetic(t *testing.T) {
	// 300 plants over 50 formats, 6 each in 6 placements: exactly enough
	g := GateOf(synthTruth(300, 50, 6))
	if !g.Sufficient || g.Detectable != 300 || g.Formats != 50 || g.FormatsReady != 50 || len(g.Thin) != 0 {
		t.Errorf("a corpus at the gate's edge should pass: %+v", g)
	}
	// one plant short
	if g := GateOf(synthTruth(299, 50, 6)); g.Sufficient {
		t.Error("299 detectable plants passed a gate of 300")
	}
	// plenty of plants, but five placements each: no format is wide enough
	g = GateOf(synthTruth(600, 50, 5))
	if g.Sufficient || g.FormatsReady != 0 || len(g.Thin) != 50 {
		t.Errorf("five placements per format should not pass: %+v", g)
	}
	// 39 wide formats are not 40
	if g := GateOf(synthTruth(300, 39, 6)); g.Sufficient || g.FormatsReady != 39 {
		t.Errorf("39 formats passed a gate of 40: %+v", g)
	}
	// plants an engine's rules do not cover, and negatives, do not count
	tr := synthTruth(300, 50, 6)
	tr.Plants = append(tr.Plants, Plant{ID: "x", Format: "other", Positive: true, Variant: "v9"}, Plant{ID: "n", Format: "neg", Detectable: true})
	if g := GateOf(tr); g.Detectable != 300 || g.Formats != 50 {
		t.Errorf("undetectable plants and negatives were counted: %+v", g)
	}
	if g.MinZeroMiss != 189 || g.MinOneMiss != 280 {
		t.Errorf("the gate quotes %d and %d plants for 98%%, want 189 and 280", g.MinZeroMiss, g.MinOneMiss)
	}
}

// The planted corpus must itself pass the gate it applies (P0-25).
func TestThePlantedCorpusPassesItsOwnGate(t *testing.T) {
	c := sharedCorpus(t)
	g := GateOf(c.Truth)
	if !g.Sufficient {
		t.Fatalf("the corpus is too thin to prove 98%%: %d detectable plants, %d formats with %d placements: %+v", g.Detectable, g.FormatsReady, GatePlacements, g)
	}
	if g.Detectable < GateDetectable || g.FormatsReady < GateFormats {
		t.Errorf("%+v", g)
	}
	// every format the gate calls ready really has six distinct placements among its detectable plants
	places := map[string]map[string]bool{}
	for _, p := range c.Truth.Plants {
		if p.Positive && p.Detectable {
			if places[p.Format] == nil {
				places[p.Format] = map[string]bool{}
			}
			places[p.Format][p.Variant] = true
		}
	}
	ready := 0
	for f, vs := range places {
		if len(vs) >= GatePlacements {
			ready++
		} else if !slices.Contains(g.Thin, f) {
			t.Errorf("%s has %d placements and is not listed as thin", f, len(vs))
		}
	}
	if ready != g.FormatsReady {
		t.Errorf("the gate counts %d ready formats, a recount finds %d", g.FormatsReady, ready)
	}
	t.Logf("gate: %d detectable plants, %d of %d formats with >= %d placements, thin: %v", g.Detectable, g.FormatsReady, g.Formats, GatePlacements, g.Thin)
}
