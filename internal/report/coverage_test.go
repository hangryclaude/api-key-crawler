package report

import (
	"strings"
	"testing"
)

// A warm full run skips every source whose scanners have already read everything in it, so
// "skipped" is the normal answer and not a warning. What the page warns about is a source that
// should have been scanned and was not: the sweep handoff says warn on Failed, not on Skipped.
func TestASkippedSourceIsNotAWarningButAFailedOneIs(t *testing.T) {
	f := newFixture(t)
	quiet := healthyRun()
	quiet.Skipped, quiet.Sources = 470, 470
	quiet.Notes = []string{"blob ledger: 48392 blob(s) were not read again", "13 private source(s) were listed and left alone"}
	doc := mustRender(t, reporter(""), f, quiet, healthyLayers())
	for _, bad := range []string{"skipped in the last run", "failed in the last run", "did not cover everything"} {
		if strings.Contains(doc, bad) {
			t.Errorf("a quiet warm run raised a warning: %q", bad)
		}
	}
	if !strings.Contains(section(t, doc, "coverage"), "blob ledger: 48392") {
		t.Error("the notes of the run are still listed under Coverage")
	}

	broken := quiet
	broken.Failed = 1
	doc = mustRender(t, reporter(""), f, broken, healthyLayers())
	if !strings.Contains(doc, "1 source failed in the last run and was not scanned.") {
		t.Error("one failed source should be said, in the singular")
	}
	if !strings.Contains(section(t, doc, "coverage"), `class="warn-num">1<`) {
		t.Error("the Failed row of Coverage should be marked")
	}
}

// The run's own counts (core.RunStats grew them) are what the page shows; the inventory's
// counts only fill what the run did not report.
func TestCoverageTakesTheRunsOwnCounts(t *testing.T) {
	f := newFixture(t)
	r := reporter("")
	r.Coverage = Coverage{Repos: 13, Refs: 111, Commits: 222}
	run := healthyRun()
	run.Refs, run.Commits, run.Blobs, run.APIResources, run.Alerts = 4321, 8765, 4242, 17, 3
	cov := section(t, mustRender(t, r, f, run, healthyLayers()), "coverage")
	for _, want := range []string{"4,321", "8,765", "4,242", ">17<", "GitHub alerts imported"} {
		if !strings.Contains(cov, want) {
			t.Errorf("Coverage lacks %q", want)
		}
	}
	for _, not := range []string{">111<", ">222<"} {
		if strings.Contains(cov, not) {
			t.Errorf("Coverage shows the inventory's %s where the run reported its own", not)
		}
	}
}

// A layer that is down says what to run (core.LayerStatus.Fix), not only that it is down.
func TestALayerThatIsDownSaysWhatToRun(t *testing.T) {
	f := newFixture(t)
	layers := healthyLayers()
	layers[0].OK, layers[0].Detail, layers[0].Fix = false, "the pre-commit gate is not in the git config", "keyguard install"
	doc := section(t, mustRender(t, reporter(""), f, healthyRun(), layers), "layers")
	if !strings.Contains(doc, `Fix: <code class="cmd">keyguard install</code>`) {
		t.Errorf("the layer's fix is not on the page:\n%s", doc)
	}
	if n := strings.Count(doc, "Fix:"); n != 1 {
		t.Errorf("%d fixes shown, want 1: a working layer has nothing to run", n)
	}
}
