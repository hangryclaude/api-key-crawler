package inventory

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory/ghcli"
)

// Changed is the cheap poll, and the part of Poll that core.Inventory asks for. See Poll.
func (inv *Inventory) Changed(ctx context.Context, prev map[string]core.Source) ([]core.Source, []core.Event, error) {
	p, err := inv.Poll(ctx, prev)
	return p.Changed, p.Events, err
}

// PollStats says what a poll cost.
type PollStats struct {
	Requests    int           // REST requests made, the 304s included
	NotModified int           // of them, answered 304: no quota spent, nothing to read
	GraphQL     int           // GraphQL requests made
	Refreshed   bool          // the full GraphQL poll ran for some token; false on a quiet poll
	Duration    time.Duration // wall time on this Mac's clock: a measurement, not a cursor
}

// PollResult is everything one poll learned.
type PollResult struct {
	// Changed and Events are what core.Inventory.Changed returns. Sources whose visibility
	// flipped to exposed come first, ahead of everything else, so that scanning them in this
	// order puts a repo that just turned public before any other work.
	Changed []core.Source
	Events  []core.Event
	// Flips are the sources whose visibility differs from prev, in either direction. An opened
	// flip also yields a PublicEvent in Events when GitHub's own feed has not delivered one yet.
	Flips []Flip
	// Activity are the issues, pull requests and releases to scan, by exact page: from the events
	// of an account whose feed works, and from GraphQL for one whose feed is empty although its
	// repos are pushed (STEAL P0-21, P0-22).
	Activity []Activity
	// EventsUsable is per account, and holds only the accounts for which it is known.
	EventsUsable map[string]bool
	// Cursor is per account: the newest GitHub timestamp seen for it minus ten minutes, an overlap
	// that costs nothing because scans dedupe (STEAL P0-16). Before anything has been seen it is
	// a day before GitHub's now.
	Cursor map[string]time.Time
	// Now is GitHub's clock at the end of the poll.
	Now time.Time
	// Interval is the shortest time GitHub asks between two polls of its events endpoint
	// (X-Poll-Interval, 60 s today), the longest of the accounts'; 0 when it never said. A 304
	// does not repeat the header, so it is the value the last 200 carried. A caller that polls
	// every minute should not go faster.
	Interval time.Duration
	Stats    PollStats
}

// cursorOverlap is how far behind the newest thing seen a cursor sits.
const cursorOverlap = 10 * time.Minute

// Cursor is the point to resume from after seeing things up to newest: a little before it, so
// that two things stamped the same second or delivered out of order are not skipped.
func Cursor(newest time.Time) time.Time { return newest.Add(-cursorOverlap) }

// usableWindow is how recent a push has to be for an empty feed to count against it.
const usableWindow = 7 * 24 * time.Hour

// Poll is the cheap poll. Per token it reads the lists that reveal a push to, or a flip of, an
// exposed source with conditional requests (watch.go), per account the events feed, also
// conditional, and runs the full GraphQL query over every repo only every RefreshEvery, for the
// metadata of the private ones, or when a list could not be read. An idle poll is a handful of
// requests that all answer 304 and cost no quota. prev is the last full inventory keyed by
// Source.ID.
//
// A source is changed when it is new, when its visibility differs, or when it was pushed since
// prev. A quiet poll reports only exposed sources (public repos, their wikis, gists): a push to a
// private repo is metadata and waits for the next refresh, which is the Sweep scope. Results from
// the scopes that worked are returned even when others failed; err then joins what went wrong.
// Events are delivered once: their ETag and high-water mark are saved as soon as they are read,
// and the weekly deep scan covers anything a crashed sweep failed to act on. With no saved state,
// only events from the last day by GitHub's own clock are returned; the first full scan covers
// anything older.
//
// Poll does not ask GitHub for default branches (a git lookup per repo, seconds per page). A
// changed source keeps the branch prev recorded; one that prev lacks gets it at the next List.
//
// Every time here is GitHub's, from the Date header of its responses, and never this Mac's
// (STEAL P0-16). A feed that is empty although a repo was pushed within a week is marked
// unusable, and the activity it would have named is found through GraphQL instead (P0-21).
func (inv *Inventory) Poll(ctx context.Context, prev map[string]core.Source) (PollResult, error) {
	started := time.Now()
	inv.n.reset()
	st, stateErr := inv.loadState()
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		errs    = []error{stateErr}
		outs    []groupOut
		changed []core.Source
		events  []core.Event
		acts    []Activity
		evState = map[string]eventState{} // accounts whose feed was read
		view    = map[string][]core.Source{}
	)
	for _, g := range inv.groups() {
		wg.Go(func() {
			o := inv.pollGroup(ctx, g, prev, st)
			mu.Lock()
			defer mu.Unlock()
			outs = append(outs, o)
			changed = append(changed, o.changed...)
			errs = append(errs, o.errs...)
			for _, s := range o.view {
				view[g.via] = append(view[g.via], s)
			}
		})
	}
	for _, a := range inv.cfg.Accounts {
		wg.Go(func() {
			evs, as, ns, polled, err := inv.pollEvents(ctx, a, st.accounts[a])
			mu.Lock()
			defer mu.Unlock()
			events = append(events, evs...)
			acts = append(acts, as...)
			if polled {
				evState[a] = ns
			}
			errs = append(errs, err)
		})
	}
	wg.Wait()

	res := PollResult{EventsUsable: map[string]bool{}, Cursor: map[string]time.Time{}}
	delta := newDelta()
	if !inv.cfg.NoWatch {
		delta.watch = map[string]watchEntry{} // with the detector off, the entries it left are not touched
	}
	for _, o := range outs {
		for k, e := range o.watch {
			delta.watch[k] = e
		}
		if o.refreshed {
			delta.refreshed[o.via] = stamp(inv.now())
			res.Stats.Refreshed = true
		}
	}

	changed = dedupe(sortedCopy(changed))
	res.Flips = Flips(prev, changed)
	changed = flippedFirst(changed, res.Flips)
	events = withFlipEvents(events, res.Flips, stamp(inv.now()))

	// What each account's feed is worth, and from what time to ask again.
	now := inv.now()
	var fallback []string
	for _, a := range inv.cfg.Accounts {
		ns, ok := evState[a]
		if !ok {
			continue // the feed could not be read: the account keeps the state it had
		}
		for _, o := range outs {
			if p := o.pushed[a]; p != "" {
				ns.Pushed = newerStamp(ns.Pushed, p)
			}
		}
		for _, s := range view[a] {
			if s.Kind == "repo" && strings.EqualFold(s.Owner, a) {
				ns.Pushed = newerStamp(ns.Pushed, s.PushedAt)
			}
		}
		ns.Seen = newerStamp(ns.Seen, ns.Pushed)
		ns.Usable = judgeFeed(ns, now)
		evState[a] = ns
		if ns.Usable == triNo {
			fallback = append(fallback, a)
		}
	}

	// An account whose feed cannot be believed gets its activity from GraphQL, since the cursor.
	// The listings run side by side and write only their own slot; what they found is folded in
	// once they are all back, so nothing is shared while they run.
	type listed struct {
		acts   []Activity
		newest string
		err    error
	}
	results := make([]listed, len(fallback))
	floor := now.Add(-deliveredWindow) // what can still come back, when no listing is made
	var fb sync.WaitGroup
	for i, a := range fallback {
		since := activitySince(evState[a], now, cmp.Or(inv.cfg.EventWindow, defaultEventAge))
		if i == 0 || since.Before(floor) {
			floor = since
		}
		fb.Go(func() {
			got, newest, err := inv.listActivity(ctx, a, exposedRepos(a, view[a], prev), since)
			results[i] = listed{got, newest, err}
		})
	}
	fb.Wait()
	delivered := pruneDelivered(st.delivered, floor)
	for i, a := range fallback {
		r := results[i]
		fresh := notDelivered(r.acts, delivered)
		acts = append(acts, fresh...)
		for _, x := range fresh {
			delivered[x.URL] = x.At
		}
		errs = append(errs, r.err)
		if r.err == nil { // the cursor moves only past what was read in full
			ns := evState[a]
			ns.Seen = newerStamp(ns.Seen, r.newest)
			ns.Listed = stamp(now) // taken before the listing began, so what it missed is still ahead of it
			evState[a] = ns
		}
	}

	delta.delivered = delivered
	for a, ns := range evState {
		delta.accounts[a] = ns
		switch ns.Usable {
		case triYes:
			res.EventsUsable[a] = true
		case triNo:
			res.EventsUsable[a] = false
		}
		res.Cursor[a] = cursorTime(ns, now, cmp.Or(inv.cfg.EventWindow, defaultEventAge))
	}
	errs = append(errs, inv.saveState(st, delta))

	slices.SortStableFunc(events, func(a, b core.Event) int { return strings.Compare(a.At, b.At) })
	res.Changed, res.Events, res.Activity = changed, events, sortedActivity(activityMap(acts))
	res.Now = inv.now()
	for _, ns := range evState {
		res.Interval = max(res.Interval, time.Duration(ns.PollInterval)*time.Second)
	}
	res.Stats = PollStats{
		Requests: int(inv.n.rest.Load()), NotModified: int(inv.n.notModified.Load()), GraphQL: int(inv.n.graphql.Load()),
		Refreshed: res.Stats.Refreshed, Duration: time.Since(started),
	}
	return res, errors.Join(errs...)
}

// deliveredWindow is how long a page is remembered when no listing was made to say what can
// still come back.
const deliveredWindow = time.Hour

// pruneDelivered copies the remembered pages that a listing from floor on can still return. A
// page stays remembered for as long as the cursor is behind it, which on a quiet account is as
// long as nothing newer happens: the cursor moves with activity, not with the clock.
func pruneDelivered(old map[string]string, floor time.Time) map[string]string {
	out := map[string]string{}
	for url, at := range old {
		if t, err := time.Parse(time.RFC3339, at); err == nil && !t.Before(floor) {
			out[url] = at
		}
	}
	return out
}

// notDelivered drops the pages already handed out at the time GitHub gives them now: a page that
// was written to again has a newer time and goes out again.
func notDelivered(in []Activity, delivered map[string]string) []Activity {
	var out []Activity
	for _, a := range in {
		if !newer(a.At, delivered[a.URL]) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// groupOut is one token's share of a poll.
type groupOut struct {
	via       string
	changed   []core.Source
	view      []core.Source         // exposed sources the lists showed; nil when they were not read
	watch     map[string]watchEntry // entries to keep for the next conditional requests
	pushed    map[string]string     // account -> newest push seen to one of its own repos
	refreshed bool                  // the full GraphQL poll ran and answered
	errs      []error
}

// pollGroup reads one token's share. The cheap lists come first: their responses tell the clock
// what time GitHub thinks it is, which the decision to refresh depends on.
func (inv *Inventory) pollGroup(ctx context.Context, g group, prev map[string]core.Source, st stateFile) groupOut {
	out := groupOut{via: g.via, pushed: map[string]string{}}
	if inv.cfg.NoWatch {
		srcs, pushed, ran, err := inv.graphqlGroup(ctx, g, prev)
		out.changed, out.refreshed, out.errs = srcs, ran, []error{err}
		out.pushed[g.via] = pushed
		return out
	}
	w := inv.watchGroup(ctx, g, st.watch)
	out.watch, out.view = w.entries, w.view
	out.errs = append(out.errs, w.warns...)
	out.errs = append(out.errs, w.errs...)
	if len(w.errs) > 0 || inv.refreshDue(g.via, st) {
		// The full poll covers everything the lists would have, so it stands in for a list that
		// failed; the failure is still reported, so a broken fast path does not hide.
		srcs, pushed, ran, err := inv.graphqlGroup(ctx, g, prev)
		out.changed = append(srcs, changedOf(w.view, prev)...)
		out.refreshed = ran // a refresh GitHub did not answer is not done, and is tried again next poll
		out.errs = append(out.errs, err)
		out.pushed[g.via] = pushed
		return out
	}
	out.changed = changedOf(w.view, prev)
	// A repo prev has as public that the public list no longer shows turned private or was
	// deleted. Only a lookup by name can say which, and it is one request for all of them.
	if need := inv.disappeared(g, w.view, prev); len(need) > 0 {
		nodes, err := inv.reposByName(ctx, g.via, need)
		out.errs = append(out.errs, err)
		for _, n := range nodes {
			if n.usable() {
				out.changed = append(out.changed, changedOf(n.sources(g.via), prev)...)
			}
		}
	}
	return out
}

// judgeFeed decides whether an account's events feed can be believed. A feed with events in it
// can. An empty one is believed only while the account has not been pushed: if a repo of it was
// pushed within a week and the feed shows nothing, the feed is broken (alt-builds' is), and an
// empty feed is not a quiet account. An empty feed of a quiet account says nothing either way, so
// what was known stays.
func judgeFeed(ns eventState, now time.Time) tri {
	switch {
	case ns.Checked == "":
		return ns.Usable
	case ns.Count > 0:
		return triYes
	}
	if p, err := time.Parse(time.RFC3339, ns.Pushed); err == nil && now.Sub(p) <= usableWindow {
		return triNo
	}
	return ns.Usable
}

// cursorTime is where an account's next listing starts: the newest GitHub timestamp seen for
// it, less the overlap, or the event window before now when nothing has been seen.
func cursorTime(ns eventState, now time.Time, window time.Duration) time.Time {
	if t, err := time.Parse(time.RFC3339, ns.Seen); err == nil {
		return Cursor(t)
	}
	return now.Add(-window)
}

// activitySince is where an account's next activity listing starts: ten minutes before the start
// of the last one that came back whole, or the event window before now when none has. It moves
// with GitHub's clock and not with the things seen, so a quiet account is not listed from the same
// old page for ever.
func activitySince(ns eventState, now time.Time, window time.Duration) time.Time {
	if t, err := time.Parse(time.RFC3339, ns.Listed); err == nil {
		return Cursor(t)
	}
	return now.Add(-window)
}

// exposedRepos are the public repos of acct that the lists showed, or, when they could not be
// read, that prev knew.
func exposedRepos(acct string, view []core.Source, prev map[string]core.Source) []core.Source {
	var out []core.Source
	add := func(s core.Source) {
		if s.Kind == "repo" && s.Visibility.Exposed() && strings.EqualFold(s.Owner, acct) {
			out = append(out, s)
		}
	}
	if view != nil {
		for _, s := range view {
			add(s)
		}
	} else {
		for _, s := range prev {
			add(s)
		}
	}
	sortSources(out)
	return out
}

// sortedCopy orders sources by ID without disturbing the order of equal ones, so that when two
// routes report the same source the first one listed is the one dedupe keeps.
func sortedCopy(in []core.Source) []core.Source {
	out := slices.Clone(in)
	sortSources(out)
	return out
}

// flippedFirst puts the sources that became exposed ahead of the rest, in ID order each.
func flippedFirst(changed []core.Source, flips []Flip) []core.Source {
	first := map[string]bool{}
	for _, f := range flips {
		if f.Opened() {
			first[f.Source.ID] = true
		}
	}
	if len(first) == 0 {
		return changed
	}
	out := make([]core.Source, 0, len(changed))
	for _, s := range changed {
		if first[s.ID] {
			out = append(out, s)
		}
	}
	for _, s := range changed {
		if !first[s.ID] {
			out = append(out, s)
		}
	}
	return out
}

// withFlipEvents adds a PublicEvent for each repo that turned public, unless GitHub's feed
// already delivered one. The feed lags by minutes, and an account whose feed is empty never
// delivers any, so the flip is reported from the repo lists instead of waiting for it.
func withFlipEvents(events []core.Event, flips []Flip, at string) []core.Event {
	have := map[string]bool{}
	for _, e := range events {
		if e.Type == "PublicEvent" {
			have[e.Source] = true
		}
	}
	for _, f := range flips {
		if f.Opened() && f.Source.Kind == "repo" && !have[f.Source.ID] {
			events = append(events, core.Event{Source: f.Source.ID, Type: "PublicEvent", At: at})
		}
	}
	return events
}

func activityMap(in []Activity) map[string]Activity {
	m := map[string]Activity{}
	for _, a := range in {
		if old, ok := m[a.URL]; !ok || newer(a.At, old.At) {
			m[a.URL] = a
		}
	}
	return m
}

// changedVs is the whole definition of "changed": unseen, visibility moved, or pushed since.
func changedVs(prev map[string]core.Source, s core.Source) bool {
	p, ok := prev[s.ID]
	return !ok || p.Visibility != s.Visibility || newer(s.PushedAt, p.PushedAt)
}

// graphqlGroup is the full GraphQL poll for one token: the newest page of every scope it reads,
// the short public lists, the newest gists, in one round trip, walking on while the last repo of a
// page is still changed. pushed is the newest push to one of the account's own repos. ran says
// whether GitHub answered the query at all: a scope it could not read (an org that is gone) is an
// error beside a poll that did run, and does not make the poll one to repeat every minute.
func (inv *Inventory) graphqlGroup(ctx context.Context, g group, prev map[string]core.Source) (out []core.Source, pushed string, ran bool, err error) {
	vars := map[string]any{"n": min(inv.pageSize(), pollPageSize)}
	if g.viewer {
		vars["g"] = gistPollSize
	}
	resp, err := inv.gql(ctx, g.via, pollQuery(g), vars)
	if err != nil {
		return nil, "", false, fmt.Errorf("inventory: poll as %s: %w", g.via, err)
	}
	data, err := decodeScopes(resp)
	if err != nil {
		return nil, "", false, err
	}
	var errs []error
	if g.viewer {
		sd := data["viewer"]
		switch {
		case sd == nil || sd.Repos == nil:
			errs = append(errs, fmt.Errorf("inventory: %s is not readable as itself: %s", g.via, missing(resp, "viewer")))
		case !strings.EqualFold(sd.Login, g.via):
			errs = append(errs, fmt.Errorf("inventory: gh's token for %s belongs to %s", g.via, sd.Login))
		default:
			if len(sd.Repos.Nodes) > 0 && sd.Repos.Nodes[0] != nil {
				pushed = sd.Repos.Nodes[0].PushedAt // the page is newest push first
			}
			srcs, err := inv.pollScope(ctx, scope{via: g.via}, sd, prev)
			out, errs = append(out, srcs...), append(errs, err)
			gs, err := inv.pollGists(ctx, g.via, sd.Gists, prev)
			out, errs = append(out, gs...), append(errs, err)
		}
	}
	for i, org := range g.orgs {
		alias := fmt.Sprintf("o%d", i)
		sd := data[alias]
		if sd == nil || sd.Repos == nil {
			errs = append(errs, fmt.Errorf("inventory: org %s is not readable as %s: %s", org, g.via, missing(resp, alias)))
			continue
		}
		srcs, err := inv.pollScope(ctx, scope{via: g.via, org: org}, sd, prev)
		out, errs = append(out, srcs...), append(errs, err)
	}
	return out, pushed, true, errors.Join(errs...)
}

// pollScope applies the three ways a repo can have changed to one scope's first page.
//
//  1. Pushed: the page is ordered by push time, so the walk goes on to the next page only
//     while the last repo of the current one is still changed.
//  2. Created with an old push time (an import, a transfer): the repo count grew past what
//     prev holds, so the whole list is walked once.
//  3. Visibility flipped: that does not move pushedAt, so the short public list is compared
//     with prev instead, and any repo whose public/private state disagrees and was not
//     already seen on a page is looked up by name.
func (inv *Inventory) pollScope(ctx context.Context, sc scope, sd *scopeData, prev map[string]core.Source) ([]core.Source, error) {
	var (
		out  []core.Source
		errs []error
		seen = map[string]bool{}
	)
	eval := func(n *repoNode) bool {
		if !n.usable() {
			errs = append(errs, fmt.Errorf("inventory: skipped a repo of %s with an unusable name", sc.owner()))
			return false
		}
		repoChanged := false
		for _, s := range n.sources(sc.via) {
			if s.Kind == "repo" {
				seen[s.ID] = true
				// The poll does not ask for the default branch (see queries.go), so keep the
				// one List last recorded rather than blanking it.
				s.DefaultBranch = prev[s.ID].DefaultBranch
			}
			if changedVs(prev, s) {
				out = append(out, s)
				repoChanged = repoChanged || s.Kind == "repo"
			}
		}
		return repoChanged
	}

	known := 0
	for _, s := range prev {
		if sc.owns(s) {
			known++
		}
	}
	conn := sd.Repos
	walkAll := conn.TotalCount > known || (sd.Pub != nil && sd.Pub.PageInfo.HasNextPage)
	for pages := 0; ; pages++ {
		last := false
		for _, n := range conn.Nodes {
			if n != nil {
				last = eval(n)
			}
		}
		if !conn.PageInfo.HasNextPage || !(walkAll || last) {
			break
		}
		if conn.PageInfo.EndCursor == "" || pages >= maxPages {
			errs = append(errs, fmt.Errorf("inventory: repo pages of %s do not end", sc.owner()))
			break
		}
		next, err := inv.repoPage(ctx, sc, conn.PageInfo.EndCursor, false)
		if err != nil {
			errs = append(errs, err)
			break
		}
		conn = next
	}

	flipped, err := inv.resolveFlips(ctx, sc, sd, prev, seen)
	errs = append(errs, err)
	for _, n := range flipped {
		eval(n)
	}
	return out, errors.Join(errs...)
}

// resolveFlips returns the nodes of repos whose public/private state disagrees with prev
// and which no page walk has shown yet.
func (inv *Inventory) resolveFlips(ctx context.Context, sc scope, sd *scopeData, prev map[string]core.Source, seen map[string]bool) ([]*repoNode, error) {
	if sd.Pub == nil {
		return nil, nil
	}
	public := map[string]bool{}
	var need []string
	for _, n := range sd.Pub.Nodes {
		if n == nil || !n.usable() {
			continue
		}
		id := repoID(n.Owner.Login, n.Name)
		public[id] = true
		if p, ok := prev[id]; !seen[id] && (!ok || p.Visibility != core.Public) {
			need = append(need, id) // went public (or is new) while far down the list
		}
	}
	for id, p := range prev {
		if sc.owns(p) && p.Visibility == core.Public && !public[id] && !seen[id] {
			need = append(need, id) // no longer public: private now, or deleted
		}
	}
	slices.Sort(need)

	var (
		out  []*repoNode
		errs []error
	)
	const batch = 40
	for chunk := range slices.Chunk(need, batch) {
		nodes, err := inv.reposByName(ctx, sc.via, chunk)
		out, errs = append(out, nodes...), append(errs, err)
	}
	return out, errors.Join(errs...)
}

// reposByName looks repos up one by one. A repo that no longer exists comes back null with
// a NOT_FOUND entry and is simply absent from the result; any other error is reported.
func (inv *Inventory) reposByName(ctx context.Context, via string, ids []string) ([]*repoNode, error) {
	var valid []string
	for _, id := range ids {
		if owner, name, ok := splitRepoID(id); ok && ghcli.ValidLogin(owner) && ghcli.ValidName(name) {
			valid = append(valid, id)
		}
	}
	if len(valid) == 0 {
		return nil, nil
	}
	g, err := inv.gql(ctx, via, byNameQuery(valid), nil)
	if err != nil {
		return nil, fmt.Errorf("inventory: look up %d repos as %s: %w", len(valid), via, err)
	}
	var errs []error
	for _, e := range g.Errors {
		if e.Type != "NOT_FOUND" {
			errs = append(errs, fmt.Errorf("inventory: look up repos as %s: %w", via, e))
		}
	}
	var data map[string]*repoNode
	if err := json.Unmarshal(g.Data, &data); err != nil {
		return nil, fmt.Errorf("inventory: unreadable GraphQL data: %w", err)
	}
	var out []*repoNode
	for i := range valid {
		if n := data[fmt.Sprintf("r%d", i)]; n != nil {
			out = append(out, n)
		}
	}
	return out, errors.Join(errs...)
}

func splitRepoID(id string) (owner, name string, ok bool) {
	rest, found := strings.CutPrefix(id, "github.com/")
	if !found {
		return "", "", false
	}
	owner, name, ok = strings.Cut(rest, "/")
	return owner, name, ok && !strings.Contains(name, "/")
}

// pollGists walks the newest gists the same way pollScope walks repos: on to the next page
// only while the last gist of this one has changed.
func (inv *Inventory) pollGists(ctx context.Context, acct string, conn *gistConn, prev map[string]core.Source) ([]core.Source, error) {
	var out []core.Source
	for pages := 0; conn != nil; pages++ {
		last := false
		for _, n := range conn.Nodes {
			if n == nil || !n.usable() {
				continue
			}
			s := n.source(acct, acct)
			if last = changedVs(prev, s); last {
				out = append(out, s)
			}
		}
		if !conn.PageInfo.HasNextPage || !last || conn.PageInfo.EndCursor == "" || pages >= maxPages {
			break
		}
		next, err := inv.gistPage(ctx, acct, gistPollSize, conn.PageInfo.EndCursor)
		if err != nil {
			return out, err
		}
		conn = next
	}
	return out, nil
}
