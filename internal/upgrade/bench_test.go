package upgrade

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"keyguard/internal/bench"
	"keyguard/internal/core"
)

// truthEngine reports the plants the corpus says an engine's rules cover, by fingerprint, and
// drops one in every `drop` of them. It stands in for an engine binary: Score only needs the
// core.Engine contract and a version.
type truthEngine struct {
	version string
	drop    int
}

func (e *truthEngine) Name() string    { return "stand-in" }
func (e *truthEngine) Version() string { return e.version }
func (e *truthEngine) Available() bool { return true }
func (e *truthEngine) ScanGit(_ context.Context, repo string, _ core.Range, o core.ScanOpts, emit core.Emit) error {
	t, err := bench.LoadTruth(filepath.Dir(repo))
	if err != nil {
		return err
	}
	n := 0
	for _, p := range t.Plants {
		if !p.Positive || !p.Detectable {
			continue
		}
		if n++; e.drop > 0 && n%e.drop == 0 {
			continue
		}
		emit(core.Hit{Engine: "stand-in", FP: p.FP, Rule: "r", Type: p.Type, Len: p.Len, Shape: "x…", Loc: core.Location{Path: p.Location.Path, Line: p.Location.Line}})
	}
	return nil
}
func (e *truthEngine) ScanStaged(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}
func (e *truthEngine) ScanDir(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}

// The scorer behind the real gate: it generates one planted corpus, scores an engine on it and
// returns that engine's own row.
func TestBenchScorerScoresAnEngineOnThePlantedCorpus(t *testing.T) {
	root := t.TempDir()
	var built []string
	s := &BenchScorer{Dir: root, NewEngine: func(name, bin string, kr core.Fingerprinter) (core.Engine, error) {
		built = append(built, bin)
		if filepath.Base(bin) == "lossy" {
			return &truthEngine{version: "stand-in 7.7.8", drop: 4}, nil
		}
		return &truthEngine{version: "stand-in 7.7.7"}, nil
	}}
	full, err := s.Score(context.Background(), "stand-in", "/some/where/exact")
	if err != nil {
		t.Fatal(err)
	}
	lossy, err := s.Score(context.Background(), "stand-in", "/some/where/lossy")
	if err != nil {
		t.Fatal(err)
	}
	if full.Version != "stand-in 7.7.7" || lossy.Version != "stand-in 7.7.8" {
		t.Errorf("versions %q %q", full.Version, lossy.Version)
	}
	// it reports every plant the rules cover, once each, and nothing else
	if full.Recall != 1 || full.Precision != 1 || full.RecallAll <= 0.5 || full.RecallAll >= 1 {
		t.Errorf("a perfect engine scored %+v", full)
	}
	// one in four dropped: recall falls by about a quarter, precision stays exact
	if lossy.Recall < 0.7 || lossy.Recall > 0.8 || lossy.Precision != 1 || lossy.RecallAll >= full.RecallAll {
		t.Errorf("a lossy engine scored %+v against %+v", lossy, full)
	}
	// the gate accepts the first over the second and not the other way round, whatever the clock says
	full.Seconds, lossy.Seconds = 1, 1
	if ok, _ := Decide(lossy, full, 1.10); !ok {
		t.Error("the better engine was not accepted")
	}
	if ok, why := Decide(full, lossy, 1.10); ok {
		t.Errorf("the worse engine was accepted: %v", why)
	}
	// the corpus was generated once, in the directory given
	if len(built) != 2 {
		t.Errorf("engines built for %v", built)
	}
	if _, err := os.Stat(filepath.Join(root, "corpus", "truth.json")); err != nil {
		t.Errorf("no corpus in the scorer's directory: %v", err)
	}
	ents, _ := os.ReadDir(root)
	corpora := 0
	for _, e := range ents {
		if e.Name() == "corpus" {
			corpora++
		}
	}
	if corpora != 1 {
		t.Errorf("%d corpus directories", corpora)
	}
}

func TestBenchScorerReportsAnEngineThatFails(t *testing.T) {
	s := &BenchScorer{Dir: t.TempDir(), NewEngine: func(string, string, core.Fingerprinter) (core.Engine, error) {
		return &brokenEngine{}, nil
	}}
	if _, err := s.Score(context.Background(), "x", "/bin/x"); err == nil {
		t.Error("an engine that cannot scan the corpus was scored")
	}
}

type brokenEngine struct{ truthEngine }

func (b *brokenEngine) ScanGit(context.Context, string, core.Range, core.ScanOpts, core.Emit) error {
	return os.ErrInvalid
}
