package pattern

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"keyguard/internal/pattern/rules"
)

// loadAverage is the machine's load, as uptime prints it.
func loadAverage() string {
	out, err := exec.Command("uptime").Output()
	if err != nil {
		return "?"
	}
	s := string(out)
	if i := strings.Index(s, "load average"); i >= 0 {
		return strings.TrimSpace(s[i:])
	}
	return strings.TrimSpace(s)
}

func perfCorpusDir(t testing.TB) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".cache", "keyguard-dev", "perf", "corpus")
	if _, err := os.Stat(dir); err != nil {
		t.Skip("no perf corpus: scripts/perf/corpus.py makes one")
	}
	return dir
}

// The profile loop: which rules the matchers spend their time on over the perf corpus, costliest first.
// It is what M3 was driven by: a rule that tops this list gets a better matcher, and the list is read
// again. KEYGUARD_TIMING=1 turns it on, as the timing test beside it.
func TestProfileTheCostliestRules(t *testing.T) {
	if os.Getenv("KEYGUARD_TIMING") != "1" {
		t.Skip("set KEYGUARD_TIMING=1 to profile the rules over the perf corpus")
	}
	dir := perfCorpusDir(t)
	s := New(rules.All, rules.Global, Options{Paths: PathsNative, Threads: 2})
	s.prof = newRuleProf(len(s.table))
	var ru0, ru1 syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru0)
	start := time.Now()
	st, err := s.ScanDir(context.Background(), dir, func(Finding, []byte) {})
	wall := time.Since(start)
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru1)
	if err != nil {
		t.Fatal(err)
	}
	cpu := time.Duration(ru1.Utime.Nano()+ru1.Stime.Nano()-ru0.Utime.Nano()-ru0.Stime.Nano()) * time.Nanosecond

	type row struct {
		id                string
		lin, rx           time.Duration
		linCalls, rxCalls int64
		linBytes, rxBytes int64
		fallbacks         int64
		isLin             bool
	}
	var rows []row
	var linTotal, rxTotal time.Duration
	for i := range s.table {
		r := row{
			id: s.table[i].ID, isLin: s.rt[i].lin != nil,
			lin: time.Duration(s.prof.lin[i].ns.Load()), rx: time.Duration(s.prof.regex[i].ns.Load()),
			linCalls: s.prof.lin[i].calls.Load(), rxCalls: s.prof.regex[i].calls.Load(),
			linBytes: s.prof.lin[i].bytes.Load(), rxBytes: s.prof.regex[i].bytes.Load(),
			fallbacks: s.prof.fallbacks[i].Load(),
		}
		linTotal += r.lin
		rxTotal += r.rx
		if r.lin+r.rx > 0 {
			rows = append(rows, r)
		}
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a].lin+rows[a].rx > rows[b].lin+rows[b].rx })
	t.Logf("%.2f s wall, %.2f s cpu, %d files, %d findings, %d fallbacks (%s)", wall.Seconds(), cpu.Seconds(), st.Files, st.Findings, st.Fallbacks, loadAverage())
	t.Logf("matchers: linear %.2f s (%.1f%% of cpu), regexp %.2f s (%.1f%% of cpu)", linTotal.Seconds(), 100*linTotal.Seconds()/cpu.Seconds(),
		rxTotal.Seconds(), 100*rxTotal.Seconds()/cpu.Seconds())
	for i, r := range rows {
		if i >= 25 {
			break
		}
		kind := "regexp"
		if r.isLin {
			kind = "linear"
		}
		t.Logf("%-40s %s lin %6.3f s %8d calls %8.1f MB | regexp %6.3f s %6d calls %8.1f MB | fallbacks %d", r.id, kind,
			r.lin.Seconds(), r.linCalls, float64(r.linBytes)/1e6, r.rx.Seconds(), r.rxCalls, float64(r.rxBytes)/1e6, r.fallbacks)
	}
}
