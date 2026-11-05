package bench

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SpeedResult is how long an engine takes over one repo, and what it costs to run (STEAL
// P0-24). Speed is per repo and in seconds, not in MB/s: the cost of a scan is mostly start-up,
// rule compilation and one pass over the history, and none of it scales with bytes alone.
type SpeedResult struct {
	Engine  string `json:"engine"`
	Version string `json:"version,omitempty"`
	Repo    string `json:"repo"`
	Runs    int    `json:"runs"`
	// ColdSeconds is the first run and WarmSeconds the median of the others. The first run is cold
	// only if nothing ran the engine over this repo just before: a rule cache already built (titus
	// compiles its rules in 3 s once) and a repo already in the page cache make it as quick as the
	// rest, so the caller who wants a cold figure measures before anything else has run.
	ColdSeconds float64 `json:"cold_seconds"`
	WarmSeconds float64 `json:"warm_seconds"`
	MinSeconds  float64 `json:"min_seconds"`
	MaxSeconds  float64 `json:"max_seconds"`
	// CPUSeconds is the median user plus system time the engine's processes used in one run, and
	// PeakRSSMB the largest total resident size of the engine's process tree at any sample.
	CPUSeconds float64 `json:"cpu_seconds"`
	PeakRSSMB  float64 `json:"peak_rss_mb"`
	Error      string  `json:"error,omitempty"`
}

// MeasureSpeed calls scan runs times, one after another, and measures each call. Wall time is
// the clock, CPU is what the process's waited-for children used (so nothing else may be starting
// child processes meanwhile), and memory is sampled from the process table, because a child's
// peak resident size is not otherwise visible to the process that started it.
func MeasureSpeed(ctx context.Context, engine, version, repo string, runs int, scan func(context.Context) error) SpeedResult {
	res := SpeedResult{Engine: engine, Version: version, Repo: repo}
	var walls, cpus []float64
	for i := 0; i < runs; i++ {
		before := childCPU()
		sampled := make(chan sample, 1)
		stop := make(chan struct{})
		go func() { sampled <- samplePeakRSS(stop) }()
		start := time.Now()
		err := scan(ctx)
		wall := time.Since(start).Seconds()
		close(stop)
		sm := <-sampled
		if err != nil {
			res.Error = err.Error()
			break
		}
		walls = append(walls, wall)
		// the sampler's own ps calls are children too: take their CPU back out
		cpus = append(cpus, max(0, childCPU()-before-sm.psCPU))
		res.PeakRSSMB = max(res.PeakRSSMB, float64(sm.peakKB)/1024)
	}
	res.Runs = len(walls)
	if len(walls) == 0 {
		return res
	}
	res.ColdSeconds = walls[0]
	res.WarmSeconds = median(walls[min(1, len(walls)-1):])
	sorted := append([]float64(nil), walls...)
	sort.Float64s(sorted)
	res.MinSeconds, res.MaxSeconds = sorted[0], sorted[len(sorted)-1]
	res.CPUSeconds = median(cpus)
	return res
}

func median(xs []float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// childCPU is the user plus system CPU time, in seconds, of every child this process has
// waited for so far.
func childCPU() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &ru); err != nil {
		return 0
	}
	tv := func(t syscall.Timeval) float64 { return float64(t.Sec) + float64(t.Usec)/1e6 }
	return tv(ru.Utime) + tv(ru.Stime)
}

// sample is what the process-table sampler saw: the largest total resident size of the engine's
// processes, and the CPU the sampler itself used asking.
type sample struct {
	peakKB int
	psCPU  float64
}

// samplePeakRSS polls the process table until stop is closed and returns the largest total
// resident size, in KB, of all descendants of this process.
func samplePeakRSS(stop <-chan struct{}) sample {
	var sm sample
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		kb, cpu := descendantsRSS()
		sm.peakKB = max(sm.peakKB, kb)
		sm.psCPU += cpu
		select {
		case <-stop:
			return sm
		case <-tick.C:
		}
	}
}

// descendantsRSS sums the resident size, in KB, of every process below this one, leaving out the
// ps that is taking the reading, and says how much CPU that ps used.
func descendantsRSS() (int, float64) {
	cmd := exec.Command("ps", "-axo", "pid=,ppid=,rss=")
	out, err := cmd.StdoutPipe()
	if err != nil || cmd.Start() != nil {
		return 0, 0
	}
	self := cmd.Process.Pid
	var b strings.Builder
	buf := make([]byte, 1<<16)
	for {
		n, err := out.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	cmd.Wait()
	var cpu float64
	if st := cmd.ProcessState; st != nil {
		cpu = (st.UserTime() + st.SystemTime()).Seconds()
	}
	kids := map[int][]int{}
	rss := map[int]int{}
	for _, l := range strings.Split(b.String(), "\n") {
		f := strings.Fields(l)
		if len(f) != 3 {
			continue
		}
		pid, e1 := strconv.Atoi(f[0])
		ppid, e2 := strconv.Atoi(f[1])
		kb, e3 := strconv.Atoi(f[2])
		if e1 != nil || e2 != nil || e3 != nil || pid == self {
			continue
		}
		kids[ppid] = append(kids[ppid], pid)
		rss[pid] = kb
	}
	total := 0
	queue := append([]int(nil), kids[os.Getpid()]...)
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		total += rss[pid]
		queue = append(queue, kids[pid]...)
	}
	return total, cpu
}
