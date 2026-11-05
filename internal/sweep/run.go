package sweep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/fp"
)

// runStamp is the layout of the time at the head of a run record's name.
const runStamp = "20060102T150405.000Z"

const (
	flushHits = 5000 // hits one engine buffers before they are merged, so a noisy scan stays small
	maxNotes  = 200
)

// unit is one thing that scans: an engine, or the known matcher (engine nil).
type unit struct {
	name, version string
	engine        core.Engine
}

// run is the state of one Poll, Full, Deep or PublishCheck.
type run struct {
	r       *Runner
	kind    string
	live    bool // persist state, alert, update the inventory snapshot; false for a publish check
	store   core.Store
	units   []unit
	lock    *db.Lock
	slots   chan struct{} // bounds engine processes running at once
	started time.Time
	t0      time.Time // monotonic start, for the elapsed time
	onGH    bool      // GitHub's clock was known when the run began

	led   *ledger      // blobs already read; nil for a run that must not trust or feed it (publish check, NoLedger)
	fresh bool         // read every blob again even if the ledger has it (an explicit full rescan of one source)
	gate  sync.RWMutex // a huge source's full scan takes it whole; every other scan shares it

	queueBytes  int64 // the weight of everything the run's scan queue held when it was ordered
	ledgerSeen  int   // blobs the known pass did not read because the ledger had them
	ledgerSkips int   // engine runs not started because the range held nothing new for them
	apiToken    tokenCache

	mu       sync.Mutex // guards the store, stats, snapshot and alert bookkeeping
	stats    core.RunStats
	snap     map[string]core.Source
	snapDirt bool
	queued   map[string]core.Severity // alerts already handed to the notifier or queued this run
	hiddenN  int                      // listed sources left alone because only the user can read them
	sent     int
	deferred []core.Secret
	unsent   map[string]bool // high or critical secrets nobody could be told about, for lack of a notifier

	nmu     sync.Mutex // guards notes; separate so a note can be written while mu is held
	notes   []string
	noted   map[string]bool
	dropped int
}

// now is GitHub's clock when the inventory has read one and this Mac's otherwise (P0-16). One
// clock for everything the sweep stamps keeps a verdict's time and the time it is due again
// comparable; the Mac's has been two hours off.
func (r *Runner) now() time.Time {
	if t, ok := r.serverNow(); ok {
		return t
	}
	return r.cfg.Now().UTC()
}

func (r *Runner) serverNow() (time.Time, bool) {
	if c, ok := r.cfg.Inventory.(Clocked); ok {
		if t, ok := c.ServerNow(); ok {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// units lists what can scan right now, with a note for each engine that cannot. An engine's
// version is its own plus a hash of the rules file when it reads one, so editing the rules
// makes every source due for that engine and gives it a ledger of its own (the ones that do
// not read rules are untouched).
func (r *Runner) units() ([]unit, []string) {
	var us []unit
	var notes []string
	rules := rulesTag(r.cfg.Rules)
	for _, e := range r.cfg.Engines {
		if !e.Available() {
			notes = append(notes, "engine "+e.Name()+" is not available (is its binary installed?); skipped this run")
			continue
		}
		v := e.Version()
		if readsRules(e.Name()) {
			v += rules
		}
		us = append(us, unit{name: e.Name(), version: v, engine: e})
	}
	if k := r.cfg.Known; k != nil && k.Len() > 0 {
		us = append(us, unit{name: "known", version: knownVersion(k)})
	}
	return us, notes
}

// readsRules says which engines take ScanOpts.Rules (core.ScanOpts: betterleaks and gitleaks).
func readsRules(engine string) bool { return engine == "betterleaks" || engine == "gitleaks" }

// rulesTag is "+rules.<hash>" of the rules file's bytes, or "" when no file is configured.
// A file that cannot be read is its own tag: the engines will say why, and fixing it changes
// the tag.
func rulesTag(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "+rules.unreadable"
	}
	sum := sha256.Sum256(b)
	return "+rules." + hex.EncodeToString(sum[:5])
}

// knownVersion changes when the learned set does, which makes every source get a full known
// pass: a new learned key may already be sitting in history. A matcher that can name its
// version exactly does; otherwise the entry count stands in, which catches additions.
func knownVersion(k core.KnownMatcher) string {
	if v, ok := k.(interface{ Version() string }); ok && v.Version() != "" {
		return v.Version()
	}
	return "entries=" + strconv.Itoa(k.Len())
}

// begin checks there is something to scan with and takes the run lock. wait > 0 lets a
// short-lived caller (the publish gate) queue behind a sweep instead of failing at once.
func (r *Runner) begin(ctx context.Context, kind string, live bool, store core.Store, wait time.Duration) (*run, error) {
	rn := &run{
		r: r, kind: kind, live: live, store: store, started: r.now(), t0: time.Now(), fresh: r.cfg.Fresh,
		queued: map[string]core.Severity{}, noted: map[string]bool{}, unsent: map[string]bool{},
		slots: make(chan struct{}, r.cfg.Jobs),
	}
	_, rn.onGH = r.serverNow()
	rn.stats = core.RunStats{Kind: kind, Started: stamp(rn.started), Engines: map[string]core.EngineStats{}}
	var notes []string
	rn.units, notes = r.units()
	for _, n := range notes {
		rn.note(n)
	}
	if len(rn.units) == 0 {
		return rn, ErrNoEngines
	}
	lock, err := acquire(ctx, r.cfg.Paths.Lock, wait)
	if err != nil {
		return rn, err
	}
	rn.lock = lock
	// A publish check scans into a scratch store, so a ledger it trusted would call blobs
	// scanned whose findings never reached the real store, and one it fed would do the same
	// for the next sweep.
	if live && !r.cfg.NoLedger && r.cfg.Paths.Ledger != "" {
		rn.led = newLedger(r.cfg.Paths.Ledger, rn.note)
		rn.led.checkStore(storeSize(store))
	}
	return rn, nil
}

func acquire(ctx context.Context, path string, wait time.Duration) (*db.Lock, error) {
	deadline := time.Now().Add(wait)
	for {
		l, err := db.AcquireLock(path)
		if err == nil || !errors.Is(err, db.ErrLocked) || !time.Now().Before(deadline) {
			return l, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// note records something dropped, capped, skipped or degraded. Identical notes collapse.
func (rn *run) note(msg string) {
	rn.nmu.Lock()
	defer rn.nmu.Unlock()
	if rn.noted[msg] {
		return
	}
	rn.noted[msg] = true
	if len(rn.notes) >= maxNotes {
		rn.dropped++
		return
	}
	rn.notes = append(rn.notes, msg)
}

func (rn *run) acquireSlot(ctx context.Context) error {
	select {
	case rn.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (rn *run) releaseSlot() { <-rn.slots }

// hitBuffer collects one scan's hits and merges them in batches.
type hitBuffer struct {
	rn  *run
	src core.Source
	mu  sync.Mutex
	buf []core.Hit
	n   int
}

func (b *hitBuffer) add(h core.Hit) {
	h = b.sanitize(h)
	b.mu.Lock()
	b.buf = append(b.buf, h)
	b.n++
	var batch []core.Hit
	if len(b.buf) >= flushHits {
		batch, b.buf = b.buf, nil
	}
	b.mu.Unlock()
	if batch != nil {
		b.rn.commit(batch)
	}
}

func (b *hitBuffer) flush() {
	b.mu.Lock()
	batch := b.buf
	b.buf = nil
	b.mu.Unlock()
	b.rn.commit(batch)
}

// sanitize fills in what an engine left blank and re-masks the context. The engines are
// contracted to deliver a redacted context; the scrub is idempotent on one that is, and
// covers a normalizer that missed a value.
func (b *hitBuffer) sanitize(h core.Hit) core.Hit {
	if h.Loc.Source == "" {
		h.Loc.Source = b.src.ID
	}
	if h.Loc.Visibility == "" {
		h.Loc.Visibility = b.src.Visibility
	}
	if h.Loc.Kind == "" {
		h.Loc.Kind = b.src.Kind
	}
	h.Context = fp.Scrub(clipRunes(h.Context, 200))
	return h
}

func clipRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// commit merges a batch, re-triages what it touched and hands out the alerts that are due.
func (rn *run) commit(hits []core.Hit) {
	if len(hits) == 0 {
		return
	}
	rn.mu.Lock()
	fresh, err := rn.store.Merge(hits, stamp(rn.r.now()))
	if err != nil {
		rn.note("store: " + safeErr(err))
	}
	for _, f := range fresh {
		if s, ok := rn.store.Get(f); ok && s.Status != db.StatusIgnored {
			rn.stats.NewFPs++
		}
	}
	seen := make(map[string]bool, len(hits))
	var fps []string
	for i := range hits {
		if f := hits[i].FP; f != "" && !seen[f] {
			seen[f] = true
			fps = append(fps, f)
		}
	}
	alerts := rn.settle(fps)
	rn.mu.Unlock()
	rn.dispatch(alerts)
}

func sameClass(a, b core.Secret) bool {
	return a.Triage == b.Triage && a.TriageBy == b.TriageBy && a.TriageWhy == b.TriageWhy && a.Severity == b.Severity
}

// settle re-triages the given secrets and returns those that now deserve an alert: severity
// of high or more, above anything already sent. One rule covers a new secret, a verdict that
// turned live, a repo that went public and a second location in the open. The caller holds mu.
func (rn *run) settle(fps []string) []core.Secret {
	var alerts []core.Secret
	for _, f := range fps {
		s, ok := rn.store.Get(f)
		if !ok {
			continue
		}
		before := s
		rn.r.cfg.Triage.Classify(&s)
		if !sameClass(before, s) {
			if err := rn.store.Put(s); err != nil {
				rn.note("store: " + safeErr(err))
				continue
			}
		}
		if !rn.live || s.Severity < core.High || s.Severity <= s.Notified || s.Severity <= rn.queued[f] {
			continue
		}
		if rn.r.cfg.Notifier == nil {
			rn.unsent[f] = true
			continue
		}
		rn.queued[f] = s.Severity
		alerts = append(alerts, s)
	}
	return alerts
}

// settleAll re-triages every secret. Hits only touch the secrets they mention, but a
// visibility flip or a fresh verdict changes others, and an idle poll must still notice a
// repo that went public.
func (rn *run) settleAll() []core.Secret {
	rn.mu.Lock()
	defer rn.mu.Unlock()
	all := rn.store.Secrets()
	fps := make([]string, len(all))
	for i, s := range all {
		fps[i] = s.FP
	}
	return rn.settle(fps)
}

// dispatch sends alerts outside the lock, since a notifier may be slow. Up to MaxNotify go
// out one by one; the rest wait for a single digest at the end of the run.
func (rn *run) dispatch(alerts []core.Secret) {
	n := rn.r.cfg.Notifier
	for _, s := range alerts {
		rn.mu.Lock()
		if rn.sent >= rn.r.cfg.MaxNotify {
			rn.deferred = append(rn.deferred, s)
			rn.mu.Unlock()
			continue
		}
		rn.sent++
		rn.mu.Unlock()
		title, body := describe(s)
		err := n.Notify(title, body, s.Severity)
		rn.mu.Lock()
		if err != nil {
			delete(rn.queued, s.FP) // not sent: eligible again on the next run, and not recorded as told
			rn.mu.Unlock()
			rn.note("notify: " + safeErr(err))
			continue
		}
		rn.markNotified(s)
		rn.mu.Unlock()
	}
}

// markNotified records that the user was told about s at its current severity. It reads the
// secret fresh so it cannot overwrite a change made since the alert was composed. The
// caller holds mu.
func (rn *run) markNotified(s core.Secret) {
	cur, ok := rn.store.Get(s.FP)
	if !ok {
		return
	}
	cur.Notified = max(cur.Notified, s.Severity)
	if err := rn.store.Put(cur); err != nil {
		rn.note("store: " + safeErr(err))
	}
}

// digest sends the alerts that did not fit under MaxNotify as one notification.
func (rn *run) digest() {
	rn.mu.Lock()
	list := rn.deferred
	rn.deferred = nil
	rn.mu.Unlock()
	if len(list) == 0 {
		return
	}
	title, body, sev := describeDigest(list)
	rn.note(fmt.Sprintf("%d alert(s) beyond the limit of %d were sent as one digest", len(list), rn.r.cfg.MaxNotify))
	if err := rn.r.cfg.Notifier.Notify(title, body, sev); err != nil {
		rn.mu.Lock()
		for _, s := range list {
			delete(rn.queued, s.FP)
		}
		rn.mu.Unlock()
		rn.note("notify: " + safeErr(err))
		return
	}
	rn.mu.Lock()
	for _, s := range list {
		rn.markNotified(s)
	}
	rn.mu.Unlock()
}

// save persists the store, unless this run has lost its lock: writing then would clobber
// the run that took it over.
func (rn *run) save() error {
	if !rn.live {
		return nil
	}
	rn.mu.Lock()
	defer rn.mu.Unlock()
	if rn.lock != nil && !rn.lock.Held() {
		return ErrLockLost
	}
	return rn.store.Save()
}

// tally folds one source's outcome into the stats and, if the source is done, advances its
// inventory entry. An entry that does not advance keeps the poll reporting the source as
// changed until it is scanned in full, which is how a failed scan gets retried.
func (rn *run) tally(src core.Source, out srcOutcome) {
	rn.mu.Lock()
	defer rn.mu.Unlock()
	switch {
	case out.scanned:
		rn.stats.Scanned++
	case out.skipped:
		rn.stats.Skipped++
	}
	if out.failed {
		rn.stats.Failed++ // counted above as well, as before: Failed is what tells "broke" from "nothing new"
	}
	if rn.live && out.complete {
		rn.snap[src.ID] = src
		rn.snapDirt = true
	}
}

func (rn *run) engineStat(name string, d time.Duration, hits int, failed bool) {
	rn.mu.Lock()
	defer rn.mu.Unlock()
	e := rn.stats.Engines[name]
	e.Seconds += d.Seconds()
	e.Hits += hits
	if failed {
		e.Errors++
	}
	rn.stats.Engines[name] = e
}

// finish closes a run: re-triage everything, send what is left to say, save, record the
// stats, write the report and give the lock back. Every exit from a run goes through here.
func (rn *run) finish(ctx context.Context, runErr error) (core.RunStats, error) {
	cfg := rn.r.cfg
	defer func() {
		if rn.lock != nil {
			if err := rn.lock.Release(); err != nil && runErr == nil {
				runErr = err
			}
		}
	}()
	if rn.live {
		rn.dispatch(rn.settleAll())
		if cfg.Notifier != nil {
			rn.digest()
		} else if n := len(rn.unsent); n > 0 {
			rn.note(fmt.Sprintf("%d secret(s) are high or critical but no notifier is configured", n))
		}
		if err := rn.save(); err != nil {
			rn.note("store: " + safeErr(err))
			runErr = errors.Join(runErr, err)
		} else if rn.led != nil {
			rn.led.recordStore(storeSize(rn.store))
		}
		rn.mu.Lock()
		if rn.snapDirt && len(rn.snap) > 0 {
			if err := saveSnapshot(cfg.Paths.Inventory, rn.snap, rn.r.now()); err != nil {
				rn.note("inventory snapshot: " + safeErr(err))
			}
		}
		rn.mu.Unlock()
	}
	if tn, ok := rn.store.(interface{ TakeNotes() []string }); ok {
		for _, n := range tn.TakeNotes() {
			rn.note(n)
		}
	}
	if err := ctx.Err(); err != nil {
		rn.note("run interrupted: " + err.Error())
		runErr = errors.Join(runErr, context.Cause(ctx))
	}
	if rn.led != nil {
		rn.led.close()
	}
	if rn.live {
		rn.archiveRuns()
	}
	rn.summaryNotes()

	if rn.hiddenN > 0 {
		rn.note(fmt.Sprintf("%d private source(s) were listed and left alone: the sweep scans only what a stranger can read", rn.hiddenN))
	}
	rn.mu.Lock()
	// A run that began before the inventory had answered began before GitHub's clock was known.
	// It started as long ago as it has been running, on the clock it ends on, which keeps a
	// skewed Mac from making a run finish before it began.
	fin := rn.r.now()
	if _, ok := rn.r.serverNow(); ok && !rn.onGH {
		rn.started = fin.Add(-time.Since(rn.t0))
	}
	rn.stats.Started, rn.stats.Finished = stamp(rn.started), stamp(fin)
	rn.nmu.Lock()
	rn.stats.Notes = slices.Clone(rn.notes)
	if rn.dropped > 0 {
		rn.stats.Notes = append(rn.stats.Notes, fmt.Sprintf("… and %d more notes not shown", rn.dropped))
	}
	rn.nmu.Unlock()
	stats := rn.stats
	rn.mu.Unlock()

	if err := rn.writeStats(stats); err != nil {
		runErr = errors.Join(runErr, err)
	}
	if rn.live && cfg.Reporter != nil {
		var layers []core.LayerStatus
		if cfg.Layers != nil {
			layers = cfg.Layers()
		}
		if _, err := cfg.Reporter.Write(rn.store.Secrets(), stats, layers); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("sweep: report: %s", safeErr(err)))
		}
	}
	return stats, runErr
}

// storeSize is how many secrets the findings hold. The store counts them without copying
// them all when it can.
func storeSize(st core.Store) int {
	if l, ok := st.(interface{ Len() int }); ok {
		return l.Len()
	}
	return len(st.Secrets())
}

// runKeep is how long a run record stays in state/runs/ before it is filed away. A poll every
// ten minutes writes one a time, about 4,300 a month.
const runKeep = 30 * 24 * time.Hour

// archiveRuns files run records older than runKeep under runs/archive/<yyyymm>/. They are moved,
// never deleted. The age is the one in the record's name, which is when the run started on the
// clock that stamped it.
func (rn *run) archiveRuns() {
	dir := rn.r.cfg.Paths.Runs
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := rn.r.now().Add(-runKeep)
	moved := 0
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || len(name) < len(runStamp) {
			continue
		}
		at, err := time.Parse(runStamp, name[:len(runStamp)])
		if err != nil || !at.Before(cutoff) {
			continue
		}
		to := filepath.Join(dir, "archive", at.Format("200601"))
		if err := os.MkdirAll(to, 0o700); err != nil {
			rn.note("cannot file old run records: " + safeErr(err))
			return
		}
		if err := os.Rename(filepath.Join(dir, name), filepath.Join(to, name)); err != nil {
			rn.note("cannot file old run records: " + safeErr(err))
			return
		}
		moved++
	}
	if moved > 0 {
		rn.note(fmt.Sprintf("%d run record(s) older than 30 days were moved to runs/archive/", moved))
	}
}

// summaryNotes says what the ledger spared and how far this Mac's clock is from GitHub's.
func (rn *run) summaryNotes() {
	rn.mu.Lock()
	seen, skips := rn.ledgerSeen, rn.ledgerSkips
	rn.mu.Unlock()
	if seen > 0 || skips > 0 {
		rn.note(fmt.Sprintf("blob ledger: %d blob(s) were not read again and %d engine run(s) were not started, because nothing in them was new to that scanner version", seen, skips))
	}
	c, ok := rn.r.cfg.Inventory.(Clocked)
	if !ok {
		return
	}
	srv, ok := c.ServerNow()
	if !ok {
		return
	}
	if skew := rn.r.cfg.Now().Sub(srv); skew > time.Minute || skew < -time.Minute {
		dir := "ahead of"
		if skew < 0 {
			dir, skew = "behind", -skew
		}
		rn.note(fmt.Sprintf("this Mac's clock is %s %s GitHub's; every stamp and cursor here is on GitHub's", skew.Round(time.Minute), dir))
	}
}

// writeStats saves the run to state/runs/<time>.json. The file name carries milliseconds
// and, on a collision, a counter, so two runs in one second never overwrite each other.
func (rn *run) writeStats(stats core.RunStats) error {
	dir := rn.r.cfg.Paths.Runs
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return err
	}
	base := rn.started.Format(runStamp)
	path := filepath.Join(dir, base+".json")
	for i := 2; ; i++ {
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			break
		}
		path = filepath.Join(dir, fmt.Sprintf("%s-%d.json", base, i))
	}
	return db.WriteFileAtomicLazy(path, append(b, '\n'), 0o600)
}

// srcOutcome says what became of one source.
type srcOutcome struct {
	scanned  bool // at least one unit ran
	skipped  bool // nothing new, or it could not be processed (a note says which)
	failed   bool // it should have been processed and was not, because a sync, an engine or a save failed
	complete bool // every unit that was due finished, so the inventory entry may advance
}

// scanAll scans sources with a pool of Jobs workers in the order schedule gives: flips first,
// then biggest first, so a long scan starts early and the small ones fill the gaps.
func (rn *run) scanAll(ctx context.Context, sources []core.Source, force bool) {
	q := rn.schedule(sources)
	rn.mu.Lock()
	rn.stats.Sources += len(q)
	rn.mu.Unlock()
	jobs := make(chan queued)
	var wg sync.WaitGroup
	for range min(rn.r.cfg.Jobs, len(q)) {
		wg.Go(func() {
			for it := range jobs {
				if ctx.Err() != nil {
					rn.tally(it.src, srcOutcome{skipped: true})
					continue
				}
				rn.tally(it.src, rn.source(ctx, it.src, force))
			}
		})
	}
	for _, it := range q {
		jobs <- it
	}
	close(jobs)
	wg.Wait()
}

// visibilityOf builds the map RefreshVisibility takes from sources, later ones winning.
func visibilityOf(lists ...[]core.Source) map[string]core.Visibility {
	vis := map[string]core.Visibility{}
	for _, l := range lists {
		for _, s := range l {
			vis[s.ID] = s.Visibility
		}
	}
	return vis
}

func values(m map[string]core.Source) []core.Source {
	out := make([]core.Source, 0, len(m))
	for _, id := range slices.Sorted(maps.Keys(m)) {
		out = append(out, m[id])
	}
	return out
}

// exposed returns the sources worth scanning under Config.ExposedOnly, which is all of them
// when it is off. A source only the user can read is not fetched or scanned, but its entry in the
// inventory snapshot is brought up to date: the day it turns public the poll sees the
// visibility change and scans its whole history as a new source.
func (rn *run) exposed(list []core.Source) []core.Source {
	if !rn.r.cfg.ExposedOnly {
		return list
	}
	keep := make([]core.Source, 0, len(list))
	for _, s := range list {
		if s.Visibility.Exposed() {
			keep = append(keep, s)
			continue
		}
		rn.mu.Lock()
		rn.hiddenN++
		if rn.live && rn.snap != nil && rn.snap[s.ID] != s {
			rn.snap[s.ID] = s
			rn.snapDirt = true
		}
		rn.mu.Unlock()
	}
	return keep
}
