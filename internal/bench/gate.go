package bench

import "sort"

// What a corpus must hold before its recall figures mean anything (STEAL P0-25). Zero misses
// prove 98% recall at 95% confidence from 189 plants and one miss from 280, so the gate asks
// for 300 detectable plants, spread over at least 40 formats with at least 6 placements each so
// that the figure is about the scanners and not about one format in one file.
const (
	GateDetectable = 300
	GateFormats    = 40
	GatePlacements = 6
)

// Gate reports whether a truth file is large enough and wide enough to prove a recall claim.
type Gate struct {
	Detectable   int `json:"detectable"`
	Formats      int `json:"formats"`       // formats with at least one detectable plant
	FormatsReady int `json:"formats_ready"` // formats with at least GatePlacements distinct detectable placements
	// Thin lists the formats with detectable plants in fewer placements than the gate wants.
	Thin       []string `json:"thin,omitempty"`
	Sufficient bool     `json:"sufficient"`
	// MinZeroMiss and MinOneMiss are the plants 98% recall needs at 95% confidence with no
	// miss and with one.
	MinZeroMiss int `json:"min_plants_zero_miss"`
	MinOneMiss  int `json:"min_plants_one_miss"`
}

// formatOf is the format a plant stands for: its provider, or its type for a hand-written truth.
func formatOf(p Plant) string {
	if p.Format != "" {
		return p.Format
	}
	return p.Type
}

// GateOf measures a truth file against the gate. Only plants an engine's rules cover as planted
// count (Detectable), since those are the ones the recall target applies to.
func GateOf(t *Truth) Gate {
	g := Gate{MinZeroMiss: MinPlantsForRecall(0.98, 0), MinOneMiss: MinPlantsForRecall(0.98, 1)}
	places := map[string]map[string]bool{}
	for _, p := range t.Plants {
		if !p.Positive || !p.Detectable {
			continue
		}
		g.Detectable++
		f := formatOf(p)
		if places[f] == nil {
			places[f] = map[string]bool{}
		}
		places[f][p.Variant] = true
	}
	g.Formats = len(places)
	for f, vs := range places {
		if len(vs) >= GatePlacements {
			g.FormatsReady++
		} else {
			g.Thin = append(g.Thin, f)
		}
	}
	sort.Strings(g.Thin)
	g.Sufficient = g.Detectable >= GateDetectable && g.FormatsReady >= GateFormats
	return g
}
