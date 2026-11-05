package pattern_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"keyguard/internal/pattern"
	"keyguard/internal/pattern/rules"
)

// How long a scan of the perf corpus takes. It is a measurement, not a gate: the speed gates are judged
// by scripts/perf on a quiet machine, and this one only runs when asked (KEYGUARD_TIMING=1), because a
// timing taken beside other work says more about the other work. It prints the machine's load beside
// every number so that it can be read that way.
func TestScanSpeedOnThePerfCorpus(t *testing.T) {
	if os.Getenv("KEYGUARD_TIMING") != "1" {
		t.Skip("set KEYGUARD_TIMING=1 to time the scan of the perf corpus")
	}
	dir := perfDir(t)
	load := func() string {
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
	for _, threads := range []int{2, 6, 18} {
		s := pattern.New(rules.All, rules.Global, pattern.Options{Paths: pattern.PathsNative, Threads: threads})
		var ru0, ru1 syscall.Rusage
		syscall.Getrusage(syscall.RUSAGE_SELF, &ru0)
		start := time.Now()
		var n int
		st, err := s.ScanDir(context.Background(), dir, func(pattern.Finding, []byte) { n++ })
		wall := time.Since(start)
		syscall.Getrusage(syscall.RUSAGE_SELF, &ru1)
		if err != nil {
			t.Fatal(err)
		}
		cpu := time.Duration(ru1.Utime.Nano()+ru1.Stime.Nano()-ru0.Utime.Nano()-ru0.Stime.Nano()) * time.Nanosecond
		t.Logf("%2d threads: %.2f s wall, %.1f s cpu, %d files, %.0f MB, %d findings (%s)",
			threads, wall.Seconds(), cpu.Seconds(), st.Files, float64(st.Bytes)/1e6, n, load())
	}
}
