package sweep

import (
	"cmp"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"

	"keyguard/internal/core"
)

// queued is one source waiting for a worker.
type queued struct {
	src    core.Source
	weight int64 // bytes of pack on disk, else GitHub's size: the work a full scan of it costs
	flip   bool  // went from somewhere only the user can read to somewhere anyone can
}

// schedule orders a run's sources. A flip goes first: its history was never read, strangers
// can read it now, and every minute it waits in line behind a big private-turned-public repo
// is a minute a key in it is exposed. A flip is known from the inventory snapshot, which moves
// only after a scan that finished, so one whose first scan failed is still a flip. The rest go largest pack first, the longest-job-first
// rule that keeps a long scan from starting last and finishing alone while the small ones
// have long since drained.
func (rn *run) schedule(sources []core.Source) []queued {
	q := make([]queued, len(sources))
	rn.mu.Lock()
	snap := rn.snap
	rn.queueBytes = 0
	for i, s := range sources {
		q[i] = queued{src: s, weight: rn.weightOf(s), flip: exposureIncreased(snap[s.ID].Visibility, s.Visibility)}
		rn.queueBytes += q[i].weight
	}
	rn.mu.Unlock()
	slices.SortStableFunc(q, func(a, b queued) int {
		if a.flip != b.flip {
			if a.flip {
				return -1
			}
			return 1
		}
		if a.weight != b.weight {
			return cmp.Compare(b.weight, a.weight)
		}
		return cmp.Compare(a.src.ID, b.src.ID)
	})
	return q
}

// weightOf is the size of a source's mirror on disk, which is what a full scan reads, and
// GitHub's figure for a source not mirrored yet.
func (rn *run) weightOf(s core.Source) int64 {
	if dir := rn.r.cfg.Mirror.Path(s); dir != "" {
		if n := packBytes(dir); n > 0 {
			return n
		}
	}
	return int64(s.SizeKB) << 10
}

// packBytes sums the pack files of a git directory. Objects not yet packed (a fresh fetch of
// a few commits is stored loose) are small beside the packs and not counted.
func packBytes(gitDir string) int64 {
	packs, err := filepath.Glob(filepath.Join(gitDir, "objects", "pack", "*.pack"))
	if err != nil {
		return 0
	}
	var n int64
	for _, p := range packs {
		if fi, err := os.Stat(p); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// enter takes the right to scan. An ordinary scan shares the machine; a huge source's full
// scan takes it whole (Lock waits for the scans in flight and holds the new ones back), and
// the threads it may give each engine go up with it: one engine at the default two threads
// beside seven other sources is how a 186-second repo takes 186 seconds (STEAL K3).
func (rn *run) enter(src core.Source, repo string, plans []plan) (release func(), threads int) {
	if n, ok := rn.huge(repo, plans); ok {
		rn.gate.Lock()
		t := rn.hugeThreads(plans)
		rn.note(src.ID + ": " + humanBytes(n) + " of pack, so its full scan ran alone with " + strconv.Itoa(t) + " thread(s) per engine")
		return rn.gate.Unlock, t
	}
	rn.gate.RLock()
	return rn.gate.RUnlock, rn.r.threads
}

// huge reports whether the plans include an engine reading a pack of at least HugeBytes from
// the start, and that pack is at least as big as everything else queued put together. Only
// then does it decide how long the run takes, with nothing worth overlapping it with; measured
// on the 13 public repos (the biggest is 142 MiB of 411), giving each of two such repos the
// machine to itself made a full scan slower, not faster, because an engine stops gaining from
// threads at about four (STEAL K3) and the cores it could not use sat idle instead of scanning
// the others. An incremental scan of a huge repo is a handful of commits and shares the machine.
func (rn *run) huge(repo string, plans []plan) (int64, bool) {
	limit := rn.r.cfg.HugeBytes
	if limit < 0 {
		return 0, false
	}
	if !slices.ContainsFunc(plans, func(p plan) bool { return p.full && p.u.engine != nil }) {
		return 0, false
	}
	n := packBytes(repo)
	rn.mu.Lock()
	total := rn.queueBytes
	rn.mu.Unlock()
	return n, n >= limit && n*2 >= total
}

// hugeThreads divides the machine among the engines that will run, between 4 (past which
// betterleaks gains nothing, K3) and 8, never fewer than the ordinary share.
func (rn *run) hugeThreads(plans []plan) int {
	if t := rn.r.cfg.HugeThreads; t > 0 {
		return t
	}
	engines := 0
	for _, p := range plans {
		if p.u.engine != nil {
			engines++
		}
	}
	return max(rn.r.threads, min(8, max(4, runtime.NumCPU()/max(1, engines))))
}
