package engines

import (
	"context"
	"testing"

	"keyguard/internal/core"
)

// PLAN invariant 2: no secret-shaped literal in source or tests. The strongest check is the
// engines themselves, run over this package and the rules file.
func TestSourceHoldsNoSecretShapes(t *testing.T) {
	f := getFixture(t)
	for _, name := range Names {
		for _, dir := range []string{".", "../../rules"} {
			t.Run(name+"/"+dir, func(t *testing.T) {
				e := newEngine(t, name, f.kr)
				resetAudit()
				var hits []core.Hit
				if err := e.ScanDir(context.Background(), dir, testOpts(), func(h core.Hit) { hits = append(hits, h) }); err != nil {
					t.Fatal(err)
				}
				for _, h := range hits {
					if h.Loc.Path == "providers.txt" && name == "trufflehog" {
						// A list of provider names. Trufflehog's dictionary filter, which keyguard turns off
						// (--results=...filtered_unverified), is what kept it quiet about words that fit a
						// detector's pattern.
						continue
					}
					t.Errorf("%s flags %s:%d as %s (%s)", name, h.Loc.Path, h.Loc.Line, h.Rule, h.Shape)
				}
			})
		}
	}
}
