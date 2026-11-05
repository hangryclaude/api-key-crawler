package upgrade

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"keyguard/internal/bench"
	"keyguard/internal/core"
)

// BenchScorer scores an engine binary with the bench: one planted corpus, generated once and kept
// in a directory of its own, and one scan of it per call. NewEngine builds the engine for a binary
// and the bench keyring; cmd/keyguard passes engines.New, and a test passes a stand-in.
type BenchScorer struct {
	NewEngine func(name, bin string, kr core.Fingerprinter) (core.Engine, error)
	Seed      uint64 // zero means 1, the seed `keyguard bench` uses
	Rules     string // extra rules file for the engines that take one
	// Dir is where the corpus and the result files go (the corpus is fake keys, but Generate
	// refuses a git work tree). Empty means a new temporary directory.
	Dir     string
	Timeout time.Duration

	once   sync.Once
	corpus string
	err    error
}

func (b *BenchScorer) seed() uint64 {
	if b.Seed == 0 {
		return 1
	}
	return b.Seed
}

func (b *BenchScorer) prepare() (string, error) {
	b.once.Do(func() {
		root := b.Dir
		if root == "" {
			if root, b.err = os.MkdirTemp("", "keyguard-upgrade-bench-"); b.err != nil {
				return
			}
		}
		b.corpus = filepath.Join(root, "corpus")
		_, b.err = bench.Generate(b.corpus, bench.Options{Seed: b.seed()})
	})
	return b.corpus, b.err
}

// Score runs the engine over the corpus and returns its own row, not the pipeline's: the upgrade
// gate is about the engine alone.
func (b *BenchScorer) Score(ctx context.Context, name, bin string) (Row, error) {
	dir, err := b.prepare()
	if err != nil {
		return Row{}, err
	}
	e, err := b.NewEngine(name, bin, bench.KeyringFor(b.seed()))
	if err != nil {
		return Row{}, err
	}
	if !e.Available() {
		return Row{}, fmt.Errorf("upgrade: %s is not runnable", bin)
	}
	out, err := os.MkdirTemp(filepath.Dir(dir), "result-")
	if err != nil {
		return Row{}, err
	}
	res, err := bench.ScoreWith(ctx, []core.Engine{e}, nil, dir, bench.ScoreOptions{OutDir: out, Rules: b.Rules, EngineTimeout: b.Timeout})
	if err != nil {
		return Row{}, err
	}
	r := res.Engines[0]
	if r.Error != "" {
		return Row{}, fmt.Errorf("upgrade: %s failed on the corpus: %s", name, r.Error)
	}
	return Row{Version: r.Version, Recall: r.Recall, RecallAll: r.RecallAll, Precision: r.Precision, Seconds: r.Seconds}, nil
}
