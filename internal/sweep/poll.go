package sweep

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"keyguard/internal/core"
)

// Poll is the 10-minute job: ask the inventory what changed since last time, and scan only
// that, plus any source whose scan record shows work that is due for another reason (an
// engine upgraded, the learned-secret set grown). An idle poll costs the inventory's cheap
// check and a read of each source's record; every change in the world, a push, a new repo,
// a repo going public, a wiki edit, an issue comment, becomes work here or is said to have
// been skipped.
//
// A source's inventory entry advances only when its scan finished, so a scan that failed is
// reported as changed again by the next poll. With no inventory snapshot yet, Poll lists
// everything and scans all of it, which is the first run.
func (r *Runner) Poll(ctx context.Context) (core.RunStats, error) {
	rn, err := r.begin(ctx, "poll", true, r.cfg.Store, 0)
	if err != nil {
		return rn.aborted(), err
	}
	cfg := r.cfg
	prev, err := loadSnapshot(cfg.Paths.Inventory)
	if err != nil {
		rn.note("inventory snapshot unreadable (" + safeErr(err) + "); listing everything")
		prev = map[string]core.Source{}
	}
	rn.snap = maps.Clone(prev)

	var (
		changed  []core.Source
		events   []core.Event
		activity []Activity
		invErr   error
	)
	// changedNow is the cheap poll: the inventory's Changed, with the pages of GitHub that
	// changed as well when it can name them.
	changedNow := func(prev map[string]core.Source) ([]core.Source, []core.Event, error) {
		if ai, ok := cfg.Inventory.(ActivityInventory); ok && canNameActivity(ai) {
			c, e, a, err := ai.ChangedActivity(ctx, prev)
			activity = a
			return c, e, err
		}
		return cfg.Inventory.Changed(ctx, prev)
	}
	if len(prev) == 0 {
		// The first run: List is the authority, and Changed is asked too. It costs a few API
		// calls once, it starts the inventory's event cursor so the next poll sees only news,
		// and either one answering is enough to go on with.
		var lerr, cerr error
		var more []core.Source
		changed, lerr = cfg.Inventory.List(ctx)
		more, events, cerr = changedNow(prev)
		changed = append(changed, more...)
		switch {
		case lerr != nil && cerr != nil:
			invErr = errors.Join(lerr, cerr)
		case lerr != nil:
			rn.note("inventory list: " + safeErr(lerr))
		case cerr != nil:
			rn.note("inventory poll: " + safeErr(cerr))
		}
		if len(changed) > 0 {
			rn.note(fmt.Sprintf("no inventory snapshot yet: listed %d sources and scanning all of them", len(dedupeSources(changed))))
		}
	} else {
		changed, events, invErr = changedNow(prev)
	}
	if invErr != nil {
		// Changed returns what the scopes that worked found, with the error of those that did
		// not. Carry on with the partial result; give up only if there is none.
		rn.note("inventory: " + safeErr(invErr))
		if len(changed) == 0 && len(events) == 0 {
			return rn.finish(ctx, errors.New("sweep: inventory: "+safeErr(invErr)))
		}
	}
	changed = rn.exposed(dedupeSources(changed))
	known := maps.Clone(prev) // everything keyguard knows: last time's inventory, brought up to date
	for _, s := range changed {
		known[s.ID] = s
	}
	ew := foldEvents(events, activity, known, changed, cfg.EventURL, canNameActivity(cfg.Inventory))
	scanner := r.apiScanner()
	for _, n := range ew.notes(scanner != nil) {
		rn.note(n)
	}
	todo := append(slices.Clone(changed), rn.exposed(ew.git)...)
	todo = append(todo, rn.outgrownSources(known, todo)...)

	rn.store.RefreshVisibility(visibilityOf(values(known)))
	rn.scanAll(ctx, todo, false)
	if scanner != nil {
		maps.Copy(known, ew.sources) // sources only an event names: someone else's repo the user commented on
		if cfg.Token != nil {
			mergeAPI(ew.api, rn.pendingAPI(known))
		}
		rn.apiAll(ctx, ew.api, known, false)
	}
	rn.refresh(ctx, known, false)
	return rn.finish(ctx, nil)
}

// Full rescans every source in the inventory from the start with every engine, ignoring
// what the state files say was scanned. It refreshes live/dead verdicts, which is how a
// rotated key gets marked resolved.
func (r *Runner) Full(ctx context.Context) (core.RunStats, error) { return r.fullRun(ctx, "full") }

// Deep is Full plus the API resources (issues, pull requests, comments, releases, and Actions
// logs of public repos) of every source, for the weekly job.
func (r *Runner) Deep(ctx context.Context) (core.RunStats, error) { return r.fullRun(ctx, "deep") }

func (r *Runner) fullRun(ctx context.Context, kind string) (core.RunStats, error) {
	rn, err := r.begin(ctx, kind, true, r.cfg.Store, 0)
	if err != nil {
		return rn.aborted(), err
	}
	cfg := r.cfg
	list, err := cfg.Inventory.List(ctx)
	if err != nil {
		return rn.finish(ctx, errors.New("sweep: inventory: "+safeErr(err)))
	}
	list = dedupeSources(list)
	if len(list) == 0 {
		// A listing that comes back empty is what a failed one looks like. Scanning nothing
		// and calling it done would be a silent hole.
		return rn.finish(ctx, errors.New("sweep: the inventory is empty"))
	}
	prev, err := loadSnapshot(cfg.Paths.Inventory)
	if err != nil {
		rn.note("inventory snapshot unreadable (" + safeErr(err) + "); rewriting it")
		prev = map[string]core.Source{}
	}
	// The new snapshot holds what was listed. A source keeps its old entry until it has been
	// scanned, so one that fails is still "changed" to the next poll; one that is gone drops out.
	rn.snap = map[string]core.Source{}
	for _, s := range list {
		if p, ok := prev[s.ID]; ok {
			rn.snap[s.ID] = p
		}
	}
	rn.snapDirt = true
	rn.store.RefreshVisibility(visibilityOf(list))
	list = rn.exposed(list)
	rn.scanAll(ctx, list, true)
	if kind == "deep" {
		rn.deepAPI(ctx, list)
	}
	known := make(map[string]core.Source, len(list))
	for _, s := range list {
		known[s.ID] = s
	}
	rn.refresh(ctx, known, true)
	return rn.finish(ctx, nil)
}

// deepAPI reads every issue, pull request and release of every exposed repo, release files
// included: the weekly run that catches what no event reported. The inventory lists the pages
// and the scanner reads each by its exact URL, since a scanner told to read a whole repository
// would list and scan everything below it (the engines refuse to).
func (rn *run) deepAPI(ctx context.Context, list []core.Source) {
	if rn.r.apiScanner() == nil {
		rn.note("deep run: no API scanner is configured, so issues, pull requests and releases were not read this week")
		return
	}
	pl, ok := rn.r.cfg.Inventory.(PageLister)
	if !ok || !canListPages(rn.r.cfg.Inventory) {
		rn.note("deep run: the inventory cannot list every page of a repo, so issues, pull requests and releases were read only as events named them")
		return
	}
	var repos []core.Source
	known := map[string]core.Source{}
	for _, s := range list {
		if s.Kind == "repo" && (!rn.r.cfg.ExposedOnly || s.Visibility.Exposed()) {
			repos = append(repos, s)
			known[s.ID] = s
		}
	}
	pages, err := pl.ListPages(ctx, repos)
	if err != nil {
		rn.note("deep run: listing the pages of the repos: " + safeErr(err))
	}
	work := map[string][]string{}
	dropped := 0
	for _, a := range pages {
		src, ok := known[a.Source]
		if !ok {
			dropped++
			continue
		}
		if u, good := resourceURL(src, a.URL); good {
			work[src.ID] = addURL(work[src.ID], u)
		} else {
			dropped++
		}
	}
	if dropped > 0 {
		rn.note(fmt.Sprintf("deep run: %d page(s) the inventory listed are not pages of an exposed repo, and were not scanned", dropped))
	}
	rn.apiAll(ctx, work, known, true)
}

// outgrownSources lists the known sources, not already queued, whose scan record is out of
// date for the engines and learned set in use now. A snapshot written by something other than
// a sweep (an inventory refresh, say) names repos nobody has scanned; they land here too.
func (rn *run) outgrownSources(known map[string]core.Source, queued []core.Source) []core.Source {
	skip := make(map[string]bool, len(queued))
	for _, s := range queued {
		skip[s.ID] = true
	}
	var out []core.Source
	for _, id := range slices.Sorted(maps.Keys(known)) {
		if skip[id] || rn.r.cfg.ExposedOnly && !known[id].Visibility.Exposed() {
			continue
		}
		st, _ := loadState(rn.r.cfg.Paths.Sources, id)
		if rn.outgrown(st) {
			out = append(out, known[id])
		}
	}
	if len(out) > 0 {
		rn.note(fmt.Sprintf("%d source(s) have no up-to-date scan record for the engines in use; scanning them now", len(out)))
	}
	return out
}

// aborted is the stats of a run that never started: it could not get the lock or had no
// engine. Nothing is written for it; the error says why.
func (rn *run) aborted() core.RunStats {
	st := rn.stats
	st.Finished = stamp(rn.r.now())
	rn.nmu.Lock()
	st.Notes = append(st.Notes, rn.notes...)
	rn.nmu.Unlock()
	return st
}

func dedupeSources(in []core.Source) []core.Source {
	seen := make(map[string]bool, len(in))
	out := make([]core.Source, 0, len(in))
	for _, s := range in {
		if !seen[s.ID] {
			seen[s.ID] = true
			out = append(out, s)
		}
	}
	return out
}
