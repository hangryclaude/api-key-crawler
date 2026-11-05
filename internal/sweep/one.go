package sweep

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"keyguard/internal/core"
)

// One scans a single source: from the start when full is set, otherwise from where the last
// scan of it stopped. It is what `keyguard scan --repo` and `keyguard verify` run.
//
// It neither polls nor lists the world. Inventory.Changed hands out each queued event once,
// so a poll that was narrowed to one repo afterwards would swallow the events of every other
// repo; and a Full over a one-source list would rewrite the snapshot with that one source.
// Here the source comes from the snapshot (or one List when it is not in it yet), and only
// its own entry in the snapshot can move, and that only when the source was new to it: an
// entry that came from the snapshot is as old as the snapshot, so writing it back after the
// scan would claim the source is as current as that. The next poll sees the push, finds no
// commits the engines have not seen, and moves the entry along.
func (r *Runner) One(ctx context.Context, id string, full bool) (core.RunStats, error) {
	kind := "poll"
	if full {
		kind = "full"
	}
	rn, err := r.begin(ctx, kind, true, r.cfg.Store, 0)
	if err != nil {
		return rn.aborted(), err
	}
	// An explicit full rescan of one source (`keyguard verify`, `scan --repo --full`) reads
	// every blob and starts every engine, ledger or not: the person asked for it, and what it
	// reads still goes into the ledger for the polls after it.
	rn.fresh = rn.fresh || full
	prev, err := loadSnapshot(r.cfg.Paths.Inventory)
	if err != nil {
		rn.note("inventory snapshot unreadable (" + safeErr(err) + "); looking the source up on GitHub")
		prev = map[string]core.Source{}
	}
	rn.snap = maps.Clone(prev)
	src, ok := findSource(values(prev), id)
	fromSnapshot := ok
	if !ok {
		list, lerr := r.cfg.Inventory.List(ctx)
		if lerr != nil {
			return rn.finish(ctx, errors.New("sweep: inventory: "+safeErr(lerr)))
		}
		if src, ok = findSource(list, id); !ok {
			return rn.finish(ctx, fmt.Errorf("sweep: %s is not in the inventory", id))
		}
	}
	if r.cfg.ExposedOnly && !src.Visibility.Exposed() {
		return rn.finish(ctx, fmt.Errorf("sweep: %s is private, and the sweep scans only what a stranger can read; `publish-check` scans a repo before it goes public", id))
	}
	rn.store.RefreshVisibility(visibilityOf([]core.Source{src}))
	rn.scanAll(ctx, []core.Source{src}, full)
	if fromSnapshot {
		rn.mu.Lock()
		rn.snap, rn.snapDirt = prev, false
		rn.mu.Unlock()
	}
	return rn.finish(ctx, nil)
}
