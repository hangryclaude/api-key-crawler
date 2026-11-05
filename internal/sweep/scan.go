package sweep

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
)

// exposureIncreased is a repo going from somewhere only the user can read to somewhere a
// stranger can. That does not move pushedAt, so the poll learns of it only from the
// visibility changing.
func exposureIncreased(was, now core.Visibility) bool {
	return was != "" && !was.Exposed() && now.Exposed()
}

// source brings one source's mirror up to date and scans what its engines have not seen.
func (rn *run) source(ctx context.Context, src core.Source, force bool) srcOutcome {
	if rn.live && rn.r.cfg.ExposedOnly && !src.Visibility.Exposed() {
		rn.exposed([]core.Source{src})
		return srcOutcome{skipped: true, complete: true}
	}
	return rn.guard(ctx, src, func(ctx context.Context) srcOutcome {
		cfg := rn.r.cfg
		var st *sourceState
		fresh := rn.fresh // read every blob again, whatever the ledger says
		if rn.live {
			var note string
			if st, note = loadState(cfg.Paths.Sources, src.ID); note != "" {
				rn.note(note)
				fresh = true // a record that cannot be read is a reason to doubt the ledger beside it
			}
			if st != nil && exposureIncreased(st.Visibility, src.Visibility) {
				force, fresh = true, true // strangers can read it now: look at all of it, not at what was read before
				rn.note(fmt.Sprintf("%s went from %s to %s: scanning its whole history again", src.ID, st.Visibility, src.Visibility))
			}
		}
		_, after, err := cfg.Mirror.Sync(ctx, src)
		if err != nil {
			rn.note(src.ID + ": mirror sync failed: " + safeErr(err))
			return srcOutcome{skipped: true, failed: true}
		}
		repo := cfg.Mirror.Path(src)
		if repo == "" {
			rn.note(src.ID + ": the mirror has no path for this source")
			return srcOutcome{skipped: true, failed: true}
		}
		return rn.scanRepo(ctx, src, repo, after, st, force, fresh)
	})
}

// guard bounds one source's work in time and contains a panic to it: one repo that trips a
// bug must not blind the sweep to the other four hundred.
func (rn *run) guard(ctx context.Context, src core.Source, fn func(context.Context) srcOutcome) (out srcOutcome) {
	defer func() {
		if p := recover(); p != nil {
			rn.note(fmt.Sprintf("%s: internal error while scanning: %s", src.ID, safeText(fmt.Sprint(p))))
			out = srcOutcome{skipped: true, failed: true}
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, rn.r.cfg.SourceTimeout)
	defer cancel()
	return fn(ctx)
}

// maxExcludedTips bounds the "--not <tip>..." list one incremental scan puts on a git command
// line. macOS allows about a megabyte of arguments; 4,000 forty-character ids use a sixth.
const maxExcludedTips = 4000

// plan is one unit's share of a source's scan.
type plan struct {
	u    unit
	rng  core.Range
	full bool
}

// scanRepo scans repo, whose refs now stand at after, with every unit that is due.
func (rn *run) scanRepo(ctx context.Context, src core.Source, repo string, after map[string]string, st *sourceState, force, fresh bool) srcOutcome {
	cfg := rn.r.cfg
	after = maskRefs(after, cfg.Known)
	if rn.live && len(after) == 0 {
		// A mirror that reports no refs is trusted only after asking git: calling a repo empty
		// and recording it as scanned would hide everything pushed to it until its next push.
		if refs, err := listRefs(ctx, "git", repo); err == nil {
			after = maskRefs(refs, cfg.Known)
		}
	}
	if rn.live && len(after) == 0 {
		// An empty repo, or a wiki that does not exist: nothing to read, but it was looked at.
		// Recording that keeps it from counting as never scanned.
		if next := rn.finalize(src, st, after, nil, nil, nil); !st.sameProgress(next) {
			if err := saveState(cfg.Paths.Sources, next); err != nil {
				rn.note(src.ID + ": cannot save state: " + safeErr(err))
				return srcOutcome{skipped: true, failed: true}
			}
		}
		return srcOutcome{skipped: true, complete: true}
	}
	rn.coverage(src, after)
	plans, err := rn.plan(ctx, src, repo, st, after, force)
	if err != nil {
		rn.note(src.ID + ": " + safeErr(err))
		return srcOutcome{skipped: true, failed: true}
	}
	if len(plans) == 0 {
		// Every unit is at these tips already: do no work, and rewrite the record only if it
		// would say something new (the visibility, say).
		if rn.live {
			if next := rn.finalize(src, st, after, nil, nil, nil); !st.sameProgress(next) {
				if err := saveState(cfg.Paths.Sources, next); err != nil {
					rn.note(src.ID + ": cannot save state: " + safeErr(err))
					return srcOutcome{skipped: true, failed: true}
				}
			}
		}
		return srcOutcome{skipped: true, complete: true}
	}

	// A huge source's full scan takes the machine whole; any other shares it. Held across the
	// units, not the sync, so a fetch can overlap the scan of another source.
	release, threads := rn.enter(src, repo, plans)
	defer release()

	views := make([]*seenView, len(plans))
	for i := range plans {
		views[i] = rn.view(src, plans[i], fresh)
	}
	shared := &listings{}
	results := make([]unitResult, len(plans))
	var wg sync.WaitGroup
	for i := range plans {
		wg.Go(func() { results[i] = rn.runUnit(ctx, src, repo, plans[i], views[i], shared, threads) })
	}
	wg.Wait()

	errs := map[string]error{}
	complete := true
	ran := plans[:0:0]
	var unsupported []plan
	var finished []int // plans whose unit read its whole range
	started := false   // a unit ran, rather than finding nothing new in its range
	for i, res := range results {
		name := plans[i].u.name
		if !res.skipped {
			started = true
		}
		switch {
		case res.unsupported:
			rn.note("engine " + name + " does not support git scans; skipped")
			unsupported = append(unsupported, plans[i])
			continue // it scanned nothing, so it must not be recorded as having scanned
		case res.err != nil:
			errs[name] = res.err
			complete = false
			if !errors.Is(res.err, context.Canceled) { // a cancelled run says so once, in finish
				rn.note(fmt.Sprintf("%s: %s failed: %s", src.ID, name, safeErr(res.err)))
			}
		default:
			finished = append(finished, i)
		}
		ran = append(ran, plans[i])
	}
	// Hits first, then the state that says they were scanned: a crash between the two
	// costs a repeat scan, never a hole. The ledger is such a state, so it follows the same rule.
	if err := rn.save(); err != nil {
		rn.note(src.ID + ": cannot save findings: " + safeErr(err))
		return srcOutcome{scanned: true, failed: true}
	}
	for _, i := range finished {
		if views[i] == nil {
			continue
		}
		if err := views[i].Commit(); err != nil {
			rn.note(fmt.Sprintf("blob ledger: cannot record what %s read in %s (%s); it will read those blobs again", plans[i].u.name, src.ID, safeErr(err)))
		}
	}
	if rn.live {
		if err := saveState(cfg.Paths.Sources, rn.finalize(src, st, after, ran, unsupported, errs)); err != nil {
			rn.note(src.ID + ": cannot save state: " + safeErr(err))
			return srcOutcome{scanned: true, failed: true}
		}
	}
	return srcOutcome{scanned: started, skipped: !started, complete: complete, failed: !complete}
}

// view is a unit's window onto the ledger for one source, or nil when this run keeps no
// ledger or the unit has no way to use one (a BlobScanner that is not a LedgerBlobScanner).
//
// Only a scan from the start reads the ledger. An incremental range is the commits since the
// last scan, which is already the least there is to read, and reading it whole keeps the
// places a blob reappears (a key file copied to a second path, a revert) in the findings. Every
// scan feeds the ledger though, so that the full scan after it has nothing left to read.
func (rn *run) view(src core.Source, p plan, fresh bool) *seenView {
	if rn.led == nil {
		return nil
	}
	if p.u.engine == nil {
		if _, ok := rn.r.cfg.Blobs.(LedgerBlobScanner); !ok {
			return nil
		}
	}
	version := p.u.version
	if p.u.engine != nil && rn.r.cfg.NoVerify {
		version += "+noverify" // an engine that did not verify has not seen what one that does would
	}
	return newSeenView(rn.led.set(p.u.name, version), src.ID, fresh || !p.full)
}

// plan decides, per unit, between nothing, an incremental range and everything.
func (rn *run) plan(ctx context.Context, src core.Source, repo string, st *sourceState, after map[string]string, force bool) ([]plan, error) {
	var out []plan
	for _, u := range rn.units {
		if st.cannot(u.name, u.version) {
			continue
		}
		prog, had := st.progressOf(u.name)
		switch {
		case force || !had || prog.version != u.version:
			out = append(out, plan{u: u, rng: core.Range{All: true}, full: true})
		case maps.Equal(prog.tips, after):
			// caught up
		case len(prog.tips) > maxExcludedTips:
			// A repo with thousands of pull-request refs would need thousands of exclusions on one
			// command line. Scanning everything is slower and always right.
			rn.note(fmt.Sprintf("%s: %s has %d old tips, too many to exclude one by one; scanning everything", src.ID, u.name, len(prog.tips)))
			out = append(out, plan{u: u, rng: core.Range{All: true}, full: true})
		default:
			rng, ok, err := incrementalRange(ctx, "git", repo, prog.tips)
			if err != nil {
				return nil, err
			}
			if !ok { // every old tip is gone from the repo, so there is nothing to exclude
				out = append(out, plan{u: u, rng: core.Range{All: true}, full: true})
				continue
			}
			out = append(out, plan{u: u, rng: rng})
		}
	}
	return out, nil
}

// finalize is the state after a scan. Every engine's progress is carried over against the
// new tips (so one that did not run shows as lagging), then this run's results are applied:
// a finished unit is at the new tips, a failed incremental one keeps its old progress, and a
// failed full one forgets its record so the next run starts it over.
func (rn *run) finalize(src core.Source, old *sourceState, after map[string]string, plans, unsupported []plan, errs map[string]error) *sourceState {
	next := newState(src.ID)
	prior := map[string]progress{}
	if old != nil {
		next = old.clone()
		for name := range old.ScannedWith {
			prior[name], _ = old.progressOf(name)
		}
	}
	next.Source = src.ID
	next.Tips = maps.Clone(after)
	if next.Tips == nil {
		next.Tips = map[string]string{}
	}
	next.Visibility = src.Visibility
	next.LastScan = stamp(rn.r.now())
	for name, p := range prior {
		next.set(name, p.version, p.tips)
	}
	for _, p := range plans {
		switch err := errs[p.u.name]; {
		case err == nil:
			next.set(p.u.name, p.u.version, next.Tips)
			delete(next.Unsupported, p.u.name)
		case p.full:
			next.forget(p.u.name)
		}
	}
	for _, p := range unsupported {
		if next.Unsupported == nil {
			next.Unsupported = map[string]string{}
		}
		next.Unsupported[p.u.name] = p.u.version
	}
	if len(plans) == 0 && old == nil {
		// Nothing was due and nothing was known, which only happens for an empty source:
		// mark every unit as caught up so it is not full-scanned once it has content.
		for _, u := range rn.units {
			next.set(u.name, u.version, next.Tips)
		}
	}
	return next
}

type unitResult struct {
	err         error
	unsupported bool
	skipped     bool // the ledger showed nothing in its range that the unit had not read, so it did not start
}

// runUnit runs one engine (or the known pass) over one source and merges what it finds. It
// runs on its own goroutine, so it contains its own panics: an engine bug costs that engine
// this one source, not the process.
//
// The known pass is in-process and takes no engine slot: a learned key found in a new blob
// alerts as soon as it is matched, however many engine processes are queued ahead of it.
// An engine with a ledger is asked first whether its range holds a blob it has not read; if
// not there is nothing for it to find, and no process is started.
func (rn *run) runUnit(ctx context.Context, src core.Source, repo string, pl plan, view *seenView, shared *listings, threads int) (res unitResult) {
	cfg := rn.r.cfg
	var lst *listing
	if pl.u.engine != nil && view != nil {
		lst = shared.of(ctx, repo, pl.rng)
		if view.warm() {
			select {
			case <-lst.done:
			case <-ctx.Done():
				return unitResult{err: ctx.Err()}
			}
			if lst.err == nil && view.allSeen(lst.ids) {
				rn.mu.Lock()
				rn.ledgerSkips++
				rn.mu.Unlock()
				return unitResult{skipped: true}
			}
		}
	}
	if pl.u.engine != nil {
		if err := rn.acquireSlot(ctx); err != nil {
			return unitResult{err: err}
		}
		defer rn.releaseSlot()
	}

	buf := &hitBuffer{rn: rn, src: src}
	start := time.Now()
	defer func() {
		if v := recover(); v != nil {
			buf.flush() // keep what was found before the panic
			res = unitResult{err: fmt.Errorf("panic: %s", safeText(fmt.Sprint(v)))}
			rn.engineStat(pl.u.name, time.Since(start), buf.n, true)
		}
	}()
	opts := core.ScanOpts{
		Verify: !cfg.NoVerify, Threads: threads, Rules: cfg.Rules,
		Loc: core.Location{Source: src.ID, Kind: src.Kind, Visibility: src.Visibility},
	}
	var err error
	allSeen := false
	if pl.u.engine != nil {
		err = pl.u.engine.ScanGit(ctx, repo, pl.rng, opts, buf.add)
	} else {
		var bs BlobStats
		if lbs, ok := cfg.Blobs.(LedgerBlobScanner); ok && view != nil {
			bs, err = lbs.ScanBlobsSeen(ctx, repo, pl.rng, cfg.Known, opts.Loc, view, buf.add)
		} else {
			bs, err = cfg.Blobs.ScanBlobs(ctx, repo, pl.rng, cfg.Known, opts.Loc, buf.add)
		}
		rn.blobNotes(src, bs)
		allSeen = err == nil && bs.Blobs == 0 && bs.Seen > 0 // it listed the range and had read every blob in it
	}
	buf.flush()
	unsupported := errors.Is(err, core.ErrUnsupported)
	rn.engineStat(pl.u.name, time.Since(start), buf.n, err != nil && !unsupported)
	if unsupported {
		return unitResult{unsupported: true}
	}
	if err == nil && lst != nil {
		// The engine read this range, so what the range holds is now known to it. If the
		// listing failed the engine's work still counts, but the ledger learns nothing.
		select {
		case <-lst.done:
			if lst.err != nil {
				rn.note(fmt.Sprintf("blob ledger: could not list the blobs %s read in %s (%s); they will be read again", pl.u.name, src.ID, safeErr(lst.err)))
			} else {
				for _, id := range lst.ids {
					view.noteID(id)
				}
			}
		case <-ctx.Done():
			return unitResult{err: ctx.Err()}
		}
	}
	return unitResult{err: err, skipped: allSeen}
}

// coverage counts what a run looked at, for the report: the refs of every mirror it read, and
// the wikis and gists among the sources.
func (rn *run) coverage(src core.Source, refs map[string]string) {
	rn.mu.Lock()
	defer rn.mu.Unlock()
	rn.stats.Refs += len(refs)
	switch src.Kind {
	case "wiki":
		rn.stats.Wikis++
	case "gist":
		rn.stats.Gists++
	}
}

// blobNotes counts what the known pass read and says out loud what it left out.
func (rn *run) blobNotes(src core.Source, bs BlobStats) {
	rn.mu.Lock()
	rn.stats.Blobs += bs.Blobs
	rn.ledgerSeen += bs.Seen
	rn.mu.Unlock()
	if bs.Skipped > 0 {
		rn.note(fmt.Sprintf("%s: the known-secret pass skipped %d blob(s) over %s (%s in all), e.g. %s",
			src.ID, bs.Skipped, humanBytes(bs.Limit), humanBytes(bs.SkippedBytes), strings.Join(bs.SkippedPaths, ", ")))
	}
	if bs.Truncated > 0 {
		rn.note(fmt.Sprintf("%s: %d blob(s) held more than %d learned-secret matches; only the first %d of each were kept",
			src.ID, bs.Truncated, maxMatchesPerBlob, maxMatchesPerBlob))
	}
}

// outgrown reports whether a source's record shows scanning that is due although nothing was
// pushed: it was never scanned, an engine was upgraded or added since, the learned-secret set
// grew, or an engine is behind. Pushes are the inventory's business; this covers the rest, so
// a new learned key is looked for in every repo at the next poll, not at the next push.
func (rn *run) outgrown(st *sourceState) bool {
	if st == nil {
		return true
	}
	for _, u := range rn.units {
		if st.cannot(u.name, u.version) {
			continue
		}
		if p, had := st.progressOf(u.name); !had || p.version != u.version || !maps.Equal(p.tips, st.Tips) {
			return true
		}
	}
	return false
}

// humanBytes is a size for a note: 100 B, 3 KiB, 50 MiB.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%d GiB", n>>30)
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}
