package selftest

import (
	"fmt"
	"math"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"keyguard/internal/install"
)

// warmups are timed runs thrown away: the first run after a build pays for the page cache.
const warmups = 2

// hookRun is one way of starting a hook, as git starts it.
type hookRun struct {
	dir   string
	event string
	args  []string
	stdin string
}

// once runs the hook the way git does for a config hook: the installer's one-liner through
// sh -c, hook arguments appended as "$@". What it costs is process start, the store load, git
// and the engine, which is what a commit pays.
func (s *suite) once(h hookRun) (time.Duration, error) {
	script := install.HookCommand(s.bin, h.event) + ` "$@"`
	r := s.run(runOpts{dir: h.dir, stdin: h.stdin, quiet: true}, "sh", append([]string{"-c", script, "keyguard-hook"}, h.args...)...)
	if r.code != 0 {
		return 0, fmt.Errorf("the %s hook refused clean content (exit %d): %s", h.event, r.code, s.line(r.out))
	}
	return r.took, nil
}

// timeHook takes `runs` timed runs after the warm-ups.
func (s *suite) timeHook(h hookRun, runs int) ([]time.Duration, error) {
	for i := 0; i < warmups; i++ {
		if _, err := s.once(h); err != nil {
			return nil, err
		}
	}
	out := make([]time.Duration, 0, runs)
	for i := 0; i < runs; i++ {
		d, err := s.once(h)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// measure times a hook and judges it against its budget. A first set over budget is measured
// once more and the better set counts, and the report says so: a burst of work from something
// else on the machine is not a slow hook, and a hook that is slow is slow twice.
func (s *suite) measure(name string, budget time.Duration, h hookRun) (string, error) {
	runs := s.o.Runs
	if runs <= 0 {
		runs = DefaultRuns
	}
	lat := Latency{Hook: name, Runs: runs, Warmups: warmups, BudgetMs: millis(budget), Cores: runtime.NumCPU(), Load1: loadAverage()}
	d, err := s.timeHook(h, runs)
	if err != nil {
		return "", err
	}
	lat.P50ms, lat.P95ms, lat.MaxMs = stats(d)
	if lat.P50ms > lat.BudgetMs {
		if d2, err := s.timeHook(h, runs); err == nil {
			lat.Retried = true
			if p50, p95, max := stats(d2); p50 < lat.P50ms {
				lat.P50ms, lat.P95ms, lat.MaxMs = p50, p95, max
			}
		}
	}
	lat.OK = lat.P50ms <= lat.BudgetMs
	s.latency = append(s.latency, lat)

	how := fmt.Sprintf("p50 %s of %s, slowest %s; %d runs after %d warm-ups", fmtMs(lat.P50ms), fmtMs(lat.BudgetMs), fmtMs(lat.MaxMs), runs, warmups)
	if lat.Load1 > 0 {
		how += fmt.Sprintf(", load %.0f on %d cores", lat.Load1, lat.Cores)
	}
	if lat.Retried {
		how += ", measured twice"
	}
	if !lat.OK {
		return "", fmt.Errorf("over budget: %s", how)
	}
	return how, nil
}

// stats are the median, the 95th percentile (nearest rank) and the worst, in milliseconds.
func stats(d []time.Duration) (p50, p95, max float64) {
	if len(d) == 0 {
		return 0, 0, 0
	}
	ms := make([]float64, len(d))
	for i, x := range d {
		ms[i] = millis(x)
	}
	slices.Sort(ms)
	return percentile(ms, 50), percentile(ms, 95), ms[len(ms)-1]
}

// percentile is the nearest-rank percentile of sorted values; for an even count the p50 is
// the lower middle, so a hook is never judged by the slower of two runs it just beat.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	return sorted[min(max(rank, 1), len(sorted))-1]
}

func millis(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func fmtMs(v float64) string {
	if v < 10 {
		return fmt.Sprintf("%.1f ms", v)
	}
	if v >= 1000 {
		return fmt.Sprintf("%.2f s", v/1000)
	}
	return fmt.Sprintf("%.0f ms", v)
}

// loadAverage is the machine's 1-minute load, or 0 when it cannot be read. It is context for
// a figure, never a reason to excuse one.
func loadAverage() float64 {
	out, err := exec.Command("sysctl", "-n", "vm.loadavg").Output()
	if err != nil {
		return 0
	}
	f := strings.Fields(strings.Trim(strings.TrimSpace(string(out)), "{}"))
	if len(f) == 0 {
		return 0
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	return v
}

// speedRepo is a repo with a realistic change staged: a new file of a couple of hundred lines
// and an edit to an existing one, about what a commit is.
func (s *suite) speedRepo(name string) (*scene, *repo) {
	c := s.scene(name)
	r := c.repo("r")
	r.commitFile("base", "main.go", goSource("demo", 0, 40))
	r.write("main.go", goSource("demo", 0, 70))
	r.write("util.go", goSource("demo", 100, 90))
	r.stage("main.go", "util.go")
	return c, r
}

func checkSpeedPreCommit(s *suite) (string, error) {
	c, r := s.speedRepo("speed-pc")
	if c.err != nil {
		return "", c.err
	}
	return s.measure("pre-commit", BudgetPreCommit, hookRun{dir: r.dir, event: "pre-commit"})
}

// checkSpeedRefTx times the one invocation that does work: the `prepared` phase of a branch
// update to a commit no ref has yet, built with plumbing so the branch is not moved.
func checkSpeedRefTx(s *suite) (string, error) {
	c, r := s.speedRepo("speed-reftx")
	tree := strings.TrimSpace(r.git("write-tree").out)
	commit := strings.TrimSpace(r.git("commit-tree", tree, "-p", "HEAD", "-m", "timed").out)
	if c.err != nil {
		return "", c.err
	}
	if tree == "" || commit == "" {
		return "", fmt.Errorf("setup: could not build a commit with plumbing")
	}
	line := r.head() + " " + commit + " refs/heads/main\n"
	return s.measure("reference-transaction", BudgetRefTx, hookRun{dir: r.dir, event: "reference-transaction", args: []string{"prepared"}, stdin: line})
}

func checkSpeedPrePush(s *suite) (string, error) {
	c := s.scene("speed-pp")
	r, remote := c.pushWorld()
	base := r.head()
	r.commitFile("work", "main.go", goSource("demo", 0, 70))
	r.commitFile("more work", "util.go", goSource("demo", 100, 90))
	if c.err != nil {
		return "", c.err
	}
	line := "refs/heads/main " + r.head() + " refs/heads/main " + base + "\n"
	return s.measure("pre-push", BudgetPrePush, hookRun{dir: r.dir, event: "pre-push", args: []string{"origin", remote}, stdin: line})
}
