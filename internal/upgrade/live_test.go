//go:build live

package upgrade

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"keyguard/internal/bench"
	"keyguard/internal/core"
	"keyguard/internal/engines"
	"keyguard/internal/testkit"
)

func TestMain(m *testing.M) { testkit.Main(m) }

// TestLiveDecision asks what the weekly job would do today, against the real releases on GitHub,
// with the engines installed on this machine as the pinned ones and the real bench as the judge.
// It reads GitHub's releases API (four requests) and downloads into a temporary directory; it
// installs nothing and writes nothing outside it. Run it with
//
//	KEYGUARD_UPGRADE_LIVE=1 go test -tags live -run TestLiveDecision -v ./internal/upgrade/
func TestLiveDecision(t *testing.T) {
	if os.Getenv("KEYGUARD_UPGRADE_LIVE") != "1" {
		t.Skip("set KEYGUARD_UPGRADE_LIVE=1 to read GitHub and run the real bench")
	}
	dir := os.Getenv("KEYGUARD_UPGRADE_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	newEngine := func(name, bin string, kr core.Fingerprinter) (core.Engine, error) {
		return engines.New(name, bin, kr)
	}
	pins := map[string]Pinned{}
	before := map[string]string{}
	for _, s := range Sources {
		path := testkit.EnginePath(t, s.Name)
		e, err := newEngine(s.Name, path, bench.KeyringFor(1))
		if err != nil {
			t.Fatal(err)
		}
		pins[s.Name] = Pinned{Path: path, Version: e.Version()}
		if before[s.Name], err = fileSHA256(path); err != nil {
			t.Fatal(err)
		}
	}
	o := &Options{
		Dir:    dir,
		Scorer: &BenchScorer{NewEngine: newEngine, Dir: dir, Timeout: 5 * time.Minute},
	}
	start := time.Now()
	out := o.CheckAll(context.Background(), pins)
	t.Logf("checked in %.1f s", time.Since(start).Seconds())
	for _, d := range out {
		b, _ := json.MarshalIndent(d, "", " ")
		t.Logf("%s\n%s", d.Engine, b)
		if d.Err != "" {
			t.Errorf("%s: %s", d.Engine, d.Err)
		}
	}
	for name, p := range pins {
		if got, _ := fileSHA256(p.Path); got != before[name] {
			t.Errorf("the pinned %s changed", name)
		}
	}
}
