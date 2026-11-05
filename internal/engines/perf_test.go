package engines

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
)

// medianRun times fn three times and returns the median; the first run also warms titus's
// compiled-rules cache and the page cache, which is what a long-lived sweep sees.
func medianRun(fn func() int) (hits int, median time.Duration) {
	var ds []time.Duration
	for range 3 {
		start := time.Now()
		hits = fn()
		ds = append(ds, time.Since(start))
	}
	slices.Sort(ds)
	return hits, ds[1]
}

// nearestRank is the p-th percentile of sorted durations by the nearest-rank method: the
// ceil(p*n)-th smallest, so p50 of 20 runs is the 10th and p95 the 19th.
func nearestRank(sorted []time.Duration, p float64) time.Duration {
	n := int(p*float64(len(sorted)) + 0.999999)
	return sorted[min(max(n, 1), len(sorted))-1]
}

func ms(d time.Duration) float64 { return float64(d) / 1e6 }

// loadavg is the 1, 5 and 15 minute load average from the kernel.
func loadavg() string {
	out, err := exec.Command("sysctl", "-n", "vm.loadavg").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// TestPerf prints wall times (go test -v -run TestPerf). Counts and seconds only: findings
// from the real mirror are never shown. The load average is printed beside them: an unrelated
// job (trufflehog over other repositories) keeps this Mac at 25 to 40 for hours, and a number
// without it cannot be compared.
func TestPerf(t *testing.T) {
	f := getFixture(t)
	t.Logf("perf load average at start %s", loadavg())
	type target struct{ label, path string }
	targets := []target{{"fixture mirror (6 commits, 13 secrets)", f.mirror}}
	if real, ok := realMirror(); ok {
		targets = append(targets, target{"headroom mirror (read-only)", real})
	}
	for _, tg := range targets {
		for _, name := range Names {
			e := newEngine(t, name, f.kr)
			hits, d := medianRun(func() int {
				n := 0
				if err := e.ScanGit(context.Background(), tg.path, core.Range{All: true}, testOpts(), func(core.Hit) { n++ }); err != nil {
					t.Fatalf("%s on %s: %v", name, tg.label, err)
				}
				return n
			})
			t.Logf("perf ScanGit All   %-38s %-11s %3d hits  %.3fs (median of 3)", tg.label, name, hits, d.Seconds())
		}
	}

	// Pre-commit: one small staged change, the shape of the hook's budget (PLAN: p50 <= 150 ms).
	// The engine call alone; the hook's known matcher and filename rules come on top.
	for _, name := range []string{"betterleaks", "gitleaks"} {
		bin := needEngine(t, name)
		wt := worktree(t)
		writeLines(t, wt, "a.txt", "line1", "line2", "TOKEN="+fake("github"))
		gitIn(wt, nil, "add", "-A")

		measure := func(label string, mk func() core.Engine) {
			var ds []time.Duration
			hits := 0
			if err := mk().ScanStaged(context.Background(), wt, stagedOpts(wt), func(core.Hit) {}); err != nil { // warm the page cache and the hash cache
				t.Fatal(err)
			}
			for range 20 {
				e := mk() // a hook is a new process: nothing remembered in memory
				hits = 0
				start := time.Now()
				if err := e.ScanStaged(context.Background(), wt, stagedOpts(wt), func(core.Hit) { hits++ }); err != nil {
					t.Fatal(err)
				}
				ds = append(ds, time.Since(start))
			}
			slices.Sort(ds)
			t.Logf("perf ScanStaged    %-38s %-11s %3d hits  p50 %.0f ms  p95 %.0f ms  min %.0f  max %.0f (20 runs)", label, name, hits,
				ms(nearestRank(ds, 0.50)), ms(nearestRank(ds, 0.95)), ms(ds[0]), ms(ds[len(ds)-1]))
		}
		measure("1 staged file", func() core.Engine {
			e, err := New(name, bin, f.kr)
			if err != nil {
				t.Fatal(err)
			}
			return e
		})
		sum, err := hashFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		cache := filepath.Join(t.TempDir(), "engine-hashes.json")
		measure("1 staged file, pinned + hash cache", func() core.Engine {
			resetPinMemo()
			e, err := New(name, bin, f.kr, WithPins(map[string]Pin{name: {SHA256: sum}}), WithHashCache(cache))
			if err != nil {
				t.Fatal(err)
			}
			return e
		})
	}

	// What the pin check costs the first time, with no cache file: each binary read once.
	for _, name := range Names {
		bin := needEngine(t, name)
		sum, err := hashFile(bin)
		if err != nil {
			t.Fatal(err)
		}
		resetPinMemo()
		start := time.Now()
		e, _ := New(name, bin, f.kr, WithPins(map[string]Pin{name: {SHA256: sum}}))
		if err := CheckPin(e); err != nil {
			t.Fatal(err)
		}
		t.Logf("perf pin check     %-38s %-11s first hash of %s %.0f ms", "no cache file", name, filepath.Base(bin), ms(time.Since(start)))
	}
	t.Log(fmt.Sprintf("perf done; load average at end %s; engine versions %s", loadavg(), versions(t, f)))
}

func versions(t *testing.T, f *fixture) string {
	s := ""
	for _, name := range Names {
		s += name + " " + newEngine(t, name, f.kr).Version() + "; "
	}
	return s
}
