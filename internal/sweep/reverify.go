package sweep

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"keyguard/internal/core"
)

// refreshMaxCommits is how many commits of one source are read one at a time. Past it a read of
// the whole source is cheaper than an engine process a commit, and is what a full run did before
// the refresh existed.
const refreshMaxCommits = 32

// A verdict ages. A live key is asked about again after core.LiveTTL, because rotation is what
// resolves it and the report should notice; a dead one after core.DeadTTL, in case the first
// answer was wrong; one the provider could not answer when its backoff says (STEAL P0-09).
// History is not rescanned for that: a scanner only reports a key's verdict when it sees the
// key, and the keyguard stores nothing it could verify without seeing it, so the commits where
// the aged keys were found are read again with verification on, and only those.
//
// A full or deep run (all) refreshes every live key and every undecided one, whatever its age,
// because the ledger lets those runs skip the very blobs that used to re-verify them as a
// side effect.
func (rn *run) refresh(ctx context.Context, known map[string]core.Source, all bool) {
	cfg := rn.r.cfg
	if cfg.NoVerify || !rn.live {
		return
	}
	var engines []unit
	for _, u := range rn.units {
		if u.engine != nil {
			engines = append(engines, u)
		}
	}
	if len(engines) == 0 {
		return
	}
	now := rn.r.now()
	targets := map[string]map[string]bool{} // source id -> commits
	keys, unplaced := 0, 0
	for _, s := range rn.store.Secrets() {
		if !needsRefresh(s, now, all) {
			continue
		}
		placed := false
		for _, l := range s.Locations {
			src, ok := known[l.Source]
			if !ok || l.Commit == "" || cfg.ExposedOnly && !src.Visibility.Exposed() {
				continue
			}
			if targets[l.Source] == nil {
				targets[l.Source] = map[string]bool{}
			}
			targets[l.Source][l.Commit] = true
			placed = true
		}
		if placed {
			keys++
		} else {
			unplaced++
		}
	}
	if unplaced > 0 && all { // a poll would repeat this every ten minutes
		rn.note(fmt.Sprintf("%d key(s) are due for re-verification but sit nowhere the sweep can re-read (an issue, a comment, a repo that is private or gone); their verdicts are as old as they were", unplaced))
	}
	if keys == 0 {
		return
	}
	ids := make([]string, 0, len(targets))
	for id := range targets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	commits := 0
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Jobs)
	for _, id := range ids {
		commits += len(targets[id])
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			rn.refreshSource(ctx, known[id], slices.Sorted(mapKeys(targets[id])), engines)
		})
	}
	wg.Wait()
	if err := rn.save(); err != nil {
		rn.note("cannot save findings: " + safeErr(err))
	}
	rn.note(fmt.Sprintf("re-verified %d key(s) by reading %d commit(s) in %d source(s) again with verification on", keys, commits, len(ids)))
}

func mapKeys[K comparable](m map[K]bool) func(yield func(K) bool) {
	return func(yield func(K) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// needsRefresh says whether a secret's verdict is due to be asked about again. A full run asks
// about every live key and every undecided one whatever its age. An unverified key is not
// asked about: it was found with verification off, or by an engine with no verifier for it, and
// either way the ledger already sends the engines back over the history when that changes
// (the ledger of an engine is keyed by its version and by whether it verified).
func needsRefresh(s core.Secret, now time.Time, all bool) bool {
	if s.Status == core.StatusIgnored {
		return false
	}
	switch s.Verified {
	case core.Live:
		return all || aged(s, now)
	case core.VerifyError:
		return all || s.VerifyDue(now)
	case core.Dead:
		return aged(s, now)
	}
	return false
}

// aged reports whether a standing verdict has outlived its TTL. The retry schedule says so
// when the store keeps one; a store that predates it (no NextVerifyAt) is judged by when the
// verdict was taken.
func aged(s core.Secret, now time.Time) bool {
	if s.NextVerifyAt != "" {
		return s.VerifyDue(now)
	}
	at, err := time.Parse(time.RFC3339, s.VerifiedAt)
	if err != nil {
		return true // a verdict with no date is one nobody can vouch for
	}
	return !now.Before(at.Add(core.VerdictTTL(s.Verified)))
}

// refreshSource re-reads the given commits of one source with every engine, verification on.
// The hits go through the same merge as any scan's, so the store's rules for verdicts apply and
// a key the provider now rejects is resolved there.
func (rn *run) refreshSource(ctx context.Context, src core.Source, commits []string, engines []unit) {
	defer func() {
		if p := recover(); p != nil {
			rn.note(fmt.Sprintf("%s: internal error while re-verifying: %s", src.ID, safeText(fmt.Sprint(p))))
		}
	}()
	cfg := rn.r.cfg
	repo := cfg.Mirror.Path(src)
	if repo == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.SourceTimeout)
	defer cancel()
	tips := make(map[string]string, len(commits))
	for _, c := range commits {
		tips[c] = c
	}
	have, err := peeledCommits(ctx, "git", repo, tips)
	if err != nil {
		rn.note(src.ID + ": cannot re-verify: " + safeErr(err))
		return
	}
	if gone := len(commits) - len(have); gone > 0 {
		rn.note(fmt.Sprintf("%s: %d commit(s) holding keys due for re-verification are no longer in the mirror", src.ID, gone))
	}
	// "c^!" is the commit and none of its parents: exactly that commit's own changes. Several
	// of them in one range are not several commits: "a^! b^!" leaves out whichever of the two is
	// the other's parent, since each excludes its parents. So it is one commit a call.
	var ranges []core.Range
	if len(have) > refreshMaxCommits {
		rn.note(fmt.Sprintf("%s: %d commits hold keys due for re-verification, too many to read one at a time; reading the whole history instead", src.ID, len(have)))
		ranges = []core.Range{{All: true}}
	} else {
		for _, c := range have {
			ranges = append(ranges, core.Range{Revs: []string{c + "^!"}})
		}
	}
	var inner sync.WaitGroup
	for _, rng := range ranges {
		for _, u := range engines {
			inner.Go(func() { rn.refreshUnit(ctx, src, repo, u, rng) })
		}
	}
	inner.Wait()
}

func (rn *run) refreshUnit(ctx context.Context, src core.Source, repo string, u unit, rng core.Range) {
	if err := rn.acquireSlot(ctx); err != nil {
		return
	}
	defer rn.releaseSlot()
	cfg := rn.r.cfg
	buf := &hitBuffer{rn: rn, src: src}
	start := time.Now()
	defer func() {
		if v := recover(); v != nil {
			buf.flush()
			rn.note(fmt.Sprintf("%s: %s panicked while re-verifying: %s", src.ID, u.name, safeText(fmt.Sprint(v))))
			rn.engineStat(u.name, time.Since(start), buf.n, true)
		}
	}()
	opts := core.ScanOpts{
		Verify: true, Threads: rn.r.threads, Rules: cfg.Rules,
		Loc: core.Location{Source: src.ID, Kind: src.Kind, Visibility: src.Visibility},
	}
	err := u.engine.ScanGit(ctx, repo, rng, opts, buf.add)
	buf.flush()
	unsupported := errors.Is(err, core.ErrUnsupported)
	rn.engineStat(u.name, time.Since(start), buf.n, err != nil && !unsupported)
	if err != nil && !unsupported && !errors.Is(err, context.Canceled) {
		rn.note(fmt.Sprintf("%s: %s failed while re-verifying: %s", src.ID, u.name, safeErr(err)))
	}
}
