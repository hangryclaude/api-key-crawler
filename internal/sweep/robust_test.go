package sweep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/fp"
)

func hasNote(st core.RunStats, sub string) bool {
	return slices.ContainsFunc(st.Notes, func(n string) bool { return strings.Contains(n, sub) })
}

func TestUnavailableEngineIsSkippedLoudlyAndCatchesUpLater(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	c1 := a.commit("one", map[string]string{"f": "1\n"})
	titus := w.engines[2]
	titus.set(func(e *gitEngine) { e.missing = true })
	r := w.runner()
	st := mustPoll(t, r)
	if !hasNote(st, "engine titus is not available") {
		t.Fatalf("notes: %v", st.Notes)
	}
	if len(titus.callList()) != 0 || st.Scanned != 1 {
		t.Fatalf("titus ran while missing: %d calls, %+v", len(titus.callList()), st)
	}
	state, _ := loadState(w.paths.Sources, w.src("a"))
	if _, ok := state.ScannedWith["titus"]; ok {
		t.Fatal("an engine that never ran must not be recorded as having scanned")
	}
	if again := mustPoll(t, r); again.Sources != 0 {
		t.Fatalf("a missing engine must not keep the source 'changed' forever: %+v", again)
	}

	c2 := a.commit("two", map[string]string{"g": "2\n"})
	w.pushed("a")
	titus.set(func(e *gitEngine) { e.missing = false }) // installed since
	w.resetCalls()
	mustPoll(t, r)
	calls := titus.callList()
	if len(calls) != 1 || !calls[0].rng.All || !slices.Equal(calls[0].commits, []string{c1, c2}) {
		t.Fatalf("a late engine must scan the whole history once: %+v", calls)
	}
	if c := w.engines[0].callList(); len(c) != 1 || c[0].rng.All {
		t.Fatalf("the others stay incremental: %+v", c)
	}
}

func TestNothingToScanWithIsAnErrorNotASilentPass(t *testing.T) {
	w := newWorld(t)
	for _, e := range w.engines {
		e.set(func(e *gitEngine) { e.missing = true })
	}
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	st, err := r.Poll(context.Background())
	if !errors.Is(err, ErrNoEngines) {
		t.Fatalf("poll with no usable engine: %v", err)
	}
	if !hasNote(st, "engine betterleaks is not available") {
		t.Fatalf("the unavailable engines should be named: %v", st.Notes)
	}
	if _, err := os.Stat(w.paths.Lock); !os.IsNotExist(err) {
		t.Fatalf("a run that never started left its lock: %v", err)
	}
	if _, err := New(Config{Paths: w.paths, Inventory: w.inv, Mirror: w.mir, Store: w.store, Triage: w.cfg.Triage}); !errors.Is(err, ErrNoEngines) {
		t.Fatalf("New with no engines and no matcher: %v", err)
	}
}

func TestNewRejectsAnIncompleteConfig(t *testing.T) {
	w := newWorld(t)
	for name, mod := range map[string]func(*Config){
		"paths":     func(c *Config) { c.Paths = core.Paths{} },
		"inventory": func(c *Config) { c.Inventory = nil },
		"mirror":    func(c *Config) { c.Mirror = nil },
		"store":     func(c *Config) { c.Store = nil },
		"triage":    func(c *Config) { c.Triage = nil },
	} {
		cfg := w.cfg
		mod(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("New accepted a config with no %s", name)
		}
	}
	r := w.runner()
	if r.cfg.Jobs != 4 || r.cfg.SourceTimeout <= 0 || r.cfg.MaxNotify != 10 || r.cfg.Blobs == nil || r.cfg.Scratch == nil || r.threads < 1 {
		t.Fatalf("defaults not filled in: %+v", r.cfg)
	}
}

func TestAPanickingEngineCostsOneSourceNotTheSweep(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	b := w.addRepo("b", core.Private)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Unverified)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	b.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	w.engines[0].set(func(e *gitEngine) { e.panicMsg, e.panicIn = "decoder blew up near "+raw, "o__b" })
	r := w.runner()
	st, err := r.Poll(context.Background())
	if err != nil {
		t.Fatalf("a panic in one engine must not fail the run: %v", err)
	}
	if !hasNote(st, "github.com/o/b: betterleaks failed: panic") {
		t.Fatalf("the panic should be a note against b: %v", st.Notes)
	}
	for _, n := range st.Notes {
		if strings.Contains(n, raw[3:]) {
			t.Fatalf("a value in a panic message reached a note (%d characters)", len(n))
		}
	}
	if st.Scanned != 2 || st.Engines["betterleaks"].Errors != 1 {
		t.Fatalf("stats: %+v", st)
	}
	if got := len(w.secret(raw).Locations); got != 2 {
		t.Fatalf("both repos' other engines still found the secret: %d locations", got)
	}
	// b did not complete, so b stays "changed": the next poll retries betterleaks there.
	w.engines[0].set(func(e *gitEngine) { e.panicMsg = "" })
	w.resetCalls()
	st = mustPoll(t, r)
	if st.Sources != 1 || len(w.engines[0].callList()) != 1 || len(w.engines[1].callList()) != 0 {
		t.Fatalf("retry: %+v, betterleaks %d calls, trufflehog %d", st, len(w.engines[0].callList()), len(w.engines[1].callList()))
	}
}

func TestSyncFailureIsANoteAndTheSourceIsRetried(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	b := w.addRepo("b", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	b.commit("one", map[string]string{"f": "1\n"})
	tok := fakeKey(t, "ghp_", 36)
	w.mir.fail[w.src("a")] = errors.New("fatal: unable to access 'https://x-access-token:" + tok + "@github.com/o/a.git/': timed out")
	r := w.runner()
	st := mustPoll(t, r)
	if st.Sources != 2 || st.Scanned != 1 || st.Skipped != 1 {
		t.Fatalf("%+v", st)
	}
	if !hasNote(st, "github.com/o/a: mirror sync failed") {
		t.Fatalf("notes: %v", st.Notes)
	}
	disk := w.allFiles()
	for _, n := range st.Notes {
		disk += n
	}
	if strings.Contains(disk, tok) || strings.Contains(disk, "x-access-token:") {
		t.Fatal("credentials from a git error reached the notes or the disk")
	}
	snap, _ := loadSnapshot(w.paths.Inventory)
	if _, ok := snap[w.src("a")]; ok || len(snap) != 1 {
		t.Fatalf("a source that could not be scanned must not enter the snapshot: %v", snap)
	}

	delete(w.mir.fail, w.src("a"))
	w.resetCalls()
	st = mustPoll(t, r)
	if st.Sources != 1 || st.Scanned != 1 {
		t.Fatalf("the failed source should come back as changed: %+v", st)
	}
}

func TestSlowSourceTimesOutWithoutAdvancing(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r) // clone the mirror and record progress while nothing is slow

	c2 := a.commit("two", map[string]string{"g": "2\n"})
	w.pushed("a")
	gate := make(chan struct{})
	defer close(gate)
	for _, e := range w.engines {
		e.set(func(e *gitEngine) { e.gate = gate })
	}
	w.cfg.SourceTimeout = 500 * time.Millisecond
	slow := w.runner()
	st, err := slow.Poll(context.Background())
	if err != nil {
		t.Fatalf("a source timeout is a note: %v", err)
	}
	if !hasNote(st, "failed: context deadline exceeded") {
		t.Fatalf("notes: %v", st.Notes)
	}
	state, _ := loadState(w.paths.Sources, w.src("a"))
	for name := range state.ScannedWith {
		if p, _ := state.progressOf(name); p.tips["refs/heads/main"] == c2 {
			t.Fatalf("%s is recorded as having scanned a commit it timed out on", name)
		}
	}
	snap, _ := loadSnapshot(w.paths.Inventory)
	if snap[w.src("a")].PushedAt == w.inv.list[0].PushedAt {
		t.Fatal("a source that timed out advanced its inventory entry, so polls would not retry it")
	}
}

func TestCancellingTheRunStopsItCleanly(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	gate := make(chan struct{})
	entered := make(chan struct{}, 16)
	for _, e := range w.engines {
		e.set(func(e *gitEngine) { e.gate, e.entered = gate, entered })
	}
	defer close(gate)
	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		st  core.RunStats
		err error
	}
	done := make(chan result)
	go func() {
		st, err := w.runner().Poll(ctx)
		done <- result{st, err}
	}()
	<-entered
	cancel()
	res := <-done
	if !errors.Is(res.err, context.Canceled) {
		t.Fatalf("err = %v", res.err)
	}
	if !hasNote(res.st, "run interrupted") || res.st.Finished == "" {
		t.Fatalf("stats: %+v", res.st)
	}
	if _, err := os.Stat(w.paths.Lock); !os.IsNotExist(err) {
		t.Fatal("an interrupted run kept the lock")
	}
	if ents, _ := os.ReadDir(w.paths.Runs); len(ents) != 1 {
		t.Fatalf("an interrupted run still records its stats: %d files", len(ents))
	}
	if _, err := os.Stat(w.paths.Inventory); err == nil {
		t.Fatal("an interrupted run advanced the inventory snapshot")
	}
}

func TestWorkersAndEngineProcessesStayWithinJobs(t *testing.T) {
	w := newWorld(t)
	w.cfg.Jobs = 3
	for i := 0; i < 10; i++ {
		r := w.addRepo("r"+string(rune('a'+i)), core.Private)
		r.commit("x", map[string]string{"f": "1\n"})
	}
	for _, e := range w.engines {
		e.set(func(e *gitEngine) { e.delay = 40 * time.Millisecond })
	}
	st := mustPoll(t, w.runner())
	if st.Scanned != 10 {
		t.Fatalf("%+v", st)
	}
	if peak := w.track.peak.Load(); peak > 3 || peak < 2 {
		t.Fatalf("with Jobs=3 engine processes should peak at 3 (and certainly run in parallel); peak was %d", peak)
	}
}

func TestEnginesRunSideBySideInOneSource(t *testing.T) {
	w := newWorld(t)
	w.cfg.Jobs = 8
	a := w.addRepo("a", core.Private)
	a.commit("x", map[string]string{"f": "1\n"})
	for _, e := range w.engines {
		e.set(func(e *gitEngine) { e.delay = 200 * time.Millisecond })
	}
	mustPoll(t, w.runner())
	// Sequential engines could never overlap; seeing all three in flight at once is proof
	// they ran together, without depending on how fast this machine happens to be.
	if peak := w.track.peak.Load(); peak != 3 {
		t.Fatalf("peak concurrency %d, want all 3 engines at once", peak)
	}
}

func TestUnsupportedEngineIsSkippedNotFailed(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("x", map[string]string{"f": "1\n"})
	w.engines[2].set(func(e *gitEngine) { e.err = core.ErrUnsupported })
	r := w.runner()
	st := mustPoll(t, r)
	if !hasNote(st, "engine titus does not support git scans") || st.Engines["titus"].Errors != 0 {
		t.Fatalf("%+v", st)
	}
	state, _ := loadState(w.paths.Sources, w.src("a"))
	if _, ok := state.ScannedWith["titus"]; ok {
		t.Fatal("an engine that scanned nothing was recorded as scanned")
	}
	if again := mustPoll(t, r); again.Sources != 0 {
		t.Fatal("an unsupported engine must not hold the source open")
	}
}

// flawedEngine reports one hit with no fingerprint and one good one.
type flawedEngine struct{ kr *fp.Keyring }

func (f *flawedEngine) Name() string    { return "flawed" }
func (f *flawedEngine) Version() string { return "1" }
func (f *flawedEngine) Available() bool { return true }
func (f *flawedEngine) ScanStaged(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}
func (f *flawedEngine) ScanDir(context.Context, string, core.ScanOpts, core.Emit) error {
	return core.ErrUnsupported
}
func (f *flawedEngine) ScanGit(ctx context.Context, repo string, r core.Range, o core.ScanOpts, emit core.Emit) error {
	emit(core.Hit{Engine: "flawed", Rule: "x", FP: "", Shape: "…", Loc: o.Loc})
	emit(core.Hit{Engine: "flawed", Rule: "x", FP: f.kr.FP("a value"), Shape: "…", Loc: o.Loc})
	return nil
}

func TestHitsWithoutFingerprintAreANoteNotAFailure(t *testing.T) {
	w := newWorld(t)
	f := &flawedEngine{w.kr}
	w.cfg.Engines = []core.Engine{f}
	a := w.addRepo("a", core.Private)
	a.commit("x", map[string]string{"f": "1\n"})
	st := mustPoll(t, w.runner())
	if !hasNote(st, "dropped 1 hit(s) with no fingerprint from engine(s) flawed") {
		t.Fatalf("notes: %v", st.Notes)
	}
	if len(w.store.Secrets()) != 1 {
		t.Fatal("the valid hit was lost with the broken one")
	}
}

func TestInventoryTrouble(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()

	// Neither List nor Changed answers on the first run: nothing is known, so the poll fails,
	// and says so without echoing the credential gh complained about.
	tok := fakeKey(t, "ghp_", 36)
	w.inv.listErr = errors.New("gh: HTTP 401 for token " + tok)
	w.inv.hardErr = errors.New("gh: HTTP 401 again")
	st, err := r.Poll(context.Background())
	if err == nil || strings.Contains(err.Error(), tok) {
		t.Fatalf("a first poll that cannot list must fail, without echoing the token: %v", err)
	}
	if st.Finished == "" || strings.Contains(strings.Join(st.Notes, "|"), tok) {
		t.Fatalf("stats %+v", st)
	}

	// Only List fails: Changed still answers, so the first run goes on with it and says so.
	w.inv.hardErr = nil
	st = mustPoll(t, r)
	if st.Scanned != 1 || !hasNote(st, "inventory list: gh: HTTP 401") {
		t.Fatalf("first poll with a failing List: %+v", st)
	}
	w.inv.listErr = nil

	// Changed fails outright: nothing is known, so the poll fails rather than passing as idle.
	w.inv.hardErr = errors.New("network is unreachable")
	if _, err := r.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("an inventory that returns nothing but an error: %v", err)
	}
	w.inv.hardErr = nil

	// Changed returns a partial result with an error: carry on, and say so.
	b := w.addRepo("b", core.Private)
	b.commit("one", map[string]string{"f": "1\n"})
	w.inv.err = errors.New("org acme-apps is not readable")
	st, err = r.Poll(context.Background())
	if err != nil || st.Scanned != 1 || !hasNote(st, "acme-apps is not readable") {
		t.Fatalf("partial inventory: %+v %v", st, err)
	}
}

func TestFullRefusesAnEmptyInventory(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	w.inv.list = nil
	if _, err := r.Full(context.Background()); err == nil || !strings.Contains(err.Error(), "inventory is empty") {
		t.Fatalf("a full run over nothing must not pass: %v", err)
	}
	snap, _ := loadSnapshot(w.paths.Inventory)
	if len(snap) != 1 {
		t.Fatalf("the snapshot was wiped by an empty listing: %v", snap)
	}
}

func TestCorruptSnapshotMeansListEverythingAgain(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	if err := os.WriteFile(w.paths.Inventory, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := mustPoll(t, r)
	if !hasNote(st, "inventory snapshot unreadable") || st.Sources != 1 {
		t.Fatalf("%+v", st)
	}
	if snap, err := loadSnapshot(w.paths.Inventory); err != nil || len(snap) != 1 {
		t.Fatalf("snapshot not rewritten: %v %v", snap, err)
	}
}

func TestFullDropsDeletedReposFromTheSnapshotAndKeepsFailedOnesDue(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	b := w.addRepo("b", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	b.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)

	w.inv.list = w.inv.list[:1]       // b was deleted on GitHub
	c := w.addRepo("c", core.Private) // and c is new but cannot be cloned
	c.commit("one", map[string]string{"f": "1\n"})
	w.mir.fail[w.src("c")] = errors.New("repository not found")
	st := mustFull(t, r)
	// a has nothing new for any engine (skipped); c could not be fetched (skipped, and failed).
	if st.Skipped != 2 || st.Failed != 1 || !hasNote(st, "github.com/o/c: mirror sync failed") {
		t.Fatalf("%+v", st)
	}
	snap, _ := loadSnapshot(w.paths.Inventory)
	if _, ok := snap[w.src("b")]; ok {
		t.Fatal("a deleted repo stayed in the inventory snapshot")
	}
	if _, ok := snap[w.src("c")]; ok {
		t.Fatal("a repo that could not be scanned entered the snapshot, so polls would never retry it")
	}
	if _, ok := snap[w.src("a")]; !ok {
		t.Fatal("a scanned repo left the snapshot")
	}
}

func TestEmptyReposAreLookedAtOnceAndScannedWhenTheyGainContent(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private) // no commits yet
	r := w.runner()
	st := mustPoll(t, r)
	if st.Skipped != 1 || st.Scanned != 0 || w.engineCalls() != 0 {
		t.Fatalf("%+v", st)
	}
	state, _ := loadState(w.paths.Sources, w.src("a"))
	if state == nil || len(state.Tips) != 0 {
		t.Fatalf("an empty repo should still get a state record: %+v", state)
	}
	if again := mustPoll(t, r); again.Sources != 0 {
		t.Fatalf("%+v", again)
	}
	c1 := a.commit("first", map[string]string{"f": "1\n"})
	w.pushed("a")
	mustPoll(t, r)
	for _, e := range w.engines {
		if c := e.callList(); len(c) != 1 || !c[0].rng.All || commitsOf(c[0]) != c1[:7] {
			t.Fatalf("%s: %+v", e.name, c)
		}
	}
}

func TestLosingTheLockMidRunStopsWritingAndKeepsTheNewHoldersLock(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	thief := "thief-token"
	w.engines[0].set(func(e *gitEngine) {
		e.hook = func() { // another run takes the lock over while this one scans
			body := "pid=1\ntoken=" + thief + "\nstarted=2026-11-03T10:00:00Z\n"
			os.WriteFile(w.paths.Lock, []byte(body), 0o600)
		}
	})
	st, err := w.runner().Poll(context.Background())
	if !errors.Is(err, ErrLockLost) {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(w.paths.Findings); serr == nil {
		t.Fatal("a run that lost its lock wrote findings anyway")
	}
	if _, serr := os.Stat(w.paths.Inventory); serr == nil {
		t.Fatal("...and advanced the inventory snapshot")
	}
	if !hasNote(st, "the run lock was taken over") {
		t.Fatalf("notes: %v", st.Notes)
	}
	b, _ := os.ReadFile(w.paths.Lock)
	if !strings.Contains(string(b), thief) {
		t.Fatalf("the old holder removed the new holder's lock: %q", b)
	}
}

func TestNoRawValueReachesAnyOutput(t *testing.T) {
	w := newWorld(t)
	known := &fakeKnown{kr: w.kr}
	w.cfg.Known = known
	a := w.addRepo("a", core.Public)
	b := w.addRepo("b", core.Private)
	prefixes := []string{"sk-", "ghp_", "AKIA", ""}
	bodies := []string{randStr(t, alnum, 48), randStr(t, alnum, 36), randStr(t, alnum, 16), randStr(t, alnum, 40)}
	raws := make([]string, len(bodies))
	for i := range raws {
		raws[i] = prefixes[i] + bodies[i]
	}
	w.plantAll(raws[0], "openai", core.Live)
	w.plantAll(raws[1], "github", core.Unverified)
	w.plantAll(raws[2], "aws", core.Dead)
	known.add(raws[3], "MY_SERVICE_TOKEN")
	a.commit("env", map[string]string{".env": "A=" + raws[0] + "\nB=" + raws[1] + "\n", "svc.txt": "token " + raws[3] + " # prod\n"})
	b.commit("env", map[string]string{"deploy.sh": "export K=" + raws[2] + "\n", "other": raws[0] + "\n"})
	// An engine that fails with the value in its message, and one that panics with it.
	w.engines[2].set(func(e *gitEngine) { e.err = errors.New("parse error near " + raws[0] + " at offset 12") })
	w.engines[1].set(func(e *gitEngine) { e.panicMsg, e.panicIn = "bad token "+raws[1], "o__b" })

	r := w.runner()
	var outputs strings.Builder
	record := func(st core.RunStats, err error) {
		if err != nil {
			outputs.WriteString(err.Error())
		}
		b, _ := json.Marshal(st)
		outputs.Write(b)
	}
	record(r.Poll(context.Background()))
	a.commit("more", map[string]string{"x": raws[1] + "\n"})
	w.pushed("a")
	record(r.Poll(context.Background()))
	record(r.Full(context.Background()))
	pr, err := r.PublishCheck(context.Background(), a.dir)
	record(pr.Stats, err)
	for _, s := range pr.Blocking {
		b, _ := json.Marshal(s)
		outputs.Write(b)
	}
	for _, n := range w.notif.list() {
		outputs.WriteString(n.title + "\n" + n.body)
	}
	b2, _ := json.Marshal(w.rep.secrets)
	outputs.Write(b2)
	everything := w.allFiles() + outputs.String()

	for i, raw := range raws {
		body := bodies[i]
		for _, piece := range []string{raw, body, body[:12], body[len(body)-12:], body[len(body)/2-6 : len(body)/2+6]} {
			if strings.Contains(everything, piece) {
				t.Fatalf("a %d-character piece of a planted value is in keyguard's output or state (value %s)", len(piece), fp.ID(w.kr.FP(raw)))
			}
		}
	}
	if w.store.Len() < 4 {
		t.Fatalf("setup: only %d secrets were found, the audit proves little", w.store.Len())
	}
}

func TestSanitizeMasksAContextThatEscapedRedaction(t *testing.T) {
	raw := fakeKey(t, "sk-", 48)
	rn := &run{}
	b := &hitBuffer{rn: rn, src: core.Source{ID: "s", Kind: "repo", Visibility: core.Public}}
	h := b.sanitize(core.Hit{Context: "key = " + raw + " # oops"})
	if strings.Contains(h.Context, raw[3:]) {
		t.Fatal("a context that escaped redaction was passed on")
	}
	if h.Loc.Source != "s" || h.Loc.Visibility != core.Public || h.Loc.Kind != "repo" {
		t.Fatalf("%+v", h.Loc)
	}
	long := b.sanitize(core.Hit{Context: strings.Repeat("é", 500)})
	if n := len([]rune(long.Context)); n != 200 {
		t.Fatalf("context not clipped: %d runes", n)
	}
}

func TestHitsAreMergedInBatchesSoMemoryStaysBounded(t *testing.T) {
	w := newWorld(t)
	var seen int
	rn := &run{r: &Runner{cfg: Config{Notifier: nil}}, store: countingStore{w.store, &seen}, queued: map[string]core.Severity{}, noted: map[string]bool{}}
	rn.r.cfg.Triage = w.cfg.Triage
	rn.r.cfg.Now = time.Now
	rn.stats.Engines = map[string]core.EngineStats{}
	b := &hitBuffer{rn: rn, src: core.Source{ID: "s", Visibility: core.Private}}
	for i := 0; i < flushHits*2+10; i++ {
		b.add(core.Hit{Engine: "e", FP: w.kr.FP("v" + string(rune('a'+i%26))), Shape: "…", Loc: core.Location{Source: "s", Line: i}})
	}
	if seen != 2 {
		t.Fatalf("%d merges before the final flush, want 2 full batches", seen)
	}
	b.flush()
	if seen != 3 {
		t.Fatalf("%d merges after flush", seen)
	}
}

type countingStore struct {
	core.Store
	n *int
}

func (c countingStore) Merge(h []core.Hit, now string) ([]string, error) {
	*c.n++
	return c.Store.Merge(h, now)
}

func TestSourcesNobodyHasScannedAreScannedEvenWithoutAPush(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	b := w.addRepo("b", core.Private)
	c1 := a.commit("one", map[string]string{"f": "1\n"})
	b.commit("one", map[string]string{"f": "1\n"})
	// A snapshot written by something other than a sweep (an inventory refresh): it names the
	// repos, so the inventory sees nothing changed, but nobody has scanned them.
	snap := map[string]core.Source{}
	for _, s := range w.inv.list {
		snap[s.ID] = s
	}
	if err := saveSnapshot(w.paths.Inventory, snap, time.Now()); err != nil {
		t.Fatal(err)
	}
	st := mustPoll(t, w.runner())
	if st.Sources != 2 || st.Scanned != 2 || !hasNote(st, "2 source(s) have no up-to-date scan record") {
		t.Fatalf("%+v", st)
	}
	for _, e := range w.engines {
		for _, c := range e.callList() {
			if !c.rng.All || (strings.HasSuffix(c.repo, "o__a.git") && c.commits[0] != c1) {
				t.Fatalf("%s: %+v", e.name, c)
			}
		}
	}
	if again := mustPoll(t, w.runner()); again.Sources != 0 {
		t.Fatalf("once scanned, a quiet poll is quiet: %+v", again)
	}
}

func TestAnEngineUpgradeIsPickedUpWithoutAPush(t *testing.T) {
	w := newWorld(t)
	for _, n := range []string{"a", "b"} {
		w.addRepo(n, core.Private).commit("one", map[string]string{"f": "1\n"})
	}
	r := w.runner()
	mustPoll(t, r)
	w.resetCalls()
	w.engines[1].set(func(e *gitEngine) { e.ver = "9.9.9" }) // trufflehog upgraded; nothing was pushed anywhere
	st := mustPoll(t, r)
	if st.Sources != 2 {
		t.Fatalf("%+v", st)
	}
	if n := len(w.engines[1].callList()); n != 2 {
		t.Fatalf("trufflehog should rescan both repos in full: %d scans", n)
	}
	if len(w.engines[0].callList())+len(w.engines[2].callList()) != 0 {
		t.Fatal("the engines that did not change must not rescan")
	}
}

func TestAnEngineThatReturnsCatchesUpWithoutAPush(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	titus := w.engines[2]
	titus.set(func(e *gitEngine) { e.missing = true })
	r := w.runner()
	mustPoll(t, r)
	titus.set(func(e *gitEngine) { e.missing = false })
	w.resetCalls()
	mustPoll(t, r)
	if len(titus.callList()) != 1 || w.engineCalls() != 1 {
		t.Fatalf("only the returning engine should scan: %d calls in all", w.engineCalls())
	}
}

func TestAnUnsupportedEngineIsRememberedUntilItsVersionChanges(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	titus := w.engines[2]
	titus.set(func(e *gitEngine) { e.err = core.ErrUnsupported })
	r := w.runner()
	mustPoll(t, r)
	state, _ := loadState(w.paths.Sources, w.src("a"))
	if state.Unsupported["titus"] != "1.0.0" {
		t.Fatalf("unsupported: %v", state.Unsupported)
	}
	w.resetCalls()
	if st := mustPoll(t, r); st.Sources != 0 || len(titus.callList()) != 0 {
		t.Fatalf("an engine known not to scan git must not make every poll sync every mirror: %+v", st)
	}
	// A new version may have grown the ability, so it is asked again, and once it works the
	// memory is cleared.
	titus.set(func(e *gitEngine) { e.ver, e.err = "2.0.0", nil })
	st := mustPoll(t, r)
	if st.Scanned != 1 || len(titus.callList()) != 1 {
		t.Fatalf("%+v, %d calls", st, len(titus.callList()))
	}
	if state, _ := loadState(w.paths.Sources, w.src("a")); len(state.Unsupported) != 0 || state.ScannedWith["titus"] != "2.0.0" {
		t.Fatalf("%+v", state)
	}
}

func TestTooManyOldTipsFallBackToAFullScanWithANote(t *testing.T) {
	w := newWorld(t)
	r := w.runner()
	rn, err := r.begin(context.Background(), "poll", true, w.store, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rn.lock.Release()
	src := core.Source{ID: w.src("a"), Kind: "repo", Visibility: core.Private}
	st := newState(src.ID)
	after := map[string]string{}
	for i := 0; i <= maxExcludedTips; i++ {
		ref := fmt.Sprintf("refs/pull/%d/head", i)
		st.Tips[ref] = fmt.Sprintf("%040x", i+1)
		after[ref] = fmt.Sprintf("%040x", i+2) // every tip moved
	}
	for _, e := range w.engines {
		st.ScannedWith[e.Name()] = e.Version()
	}
	plans, err := rn.plan(context.Background(), src, "/nonexistent", st, after, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 3 {
		t.Fatalf("%d plans", len(plans))
	}
	for _, p := range plans {
		if !p.full || !p.rng.All {
			t.Fatalf("%s should scan everything rather than exclude %d tips: %+v", p.u.name, len(st.Tips), p.rng)
		}
	}
	if !hasNote(core.RunStats{Notes: rn.notes}, "too many to exclude one by one") {
		t.Fatalf("notes: %v", rn.notes)
	}
}

// blindMirror syncs for real but reports no refs, as a careless Mirror might.
type blindMirror struct{ *gitMirror }

func (b blindMirror) Sync(ctx context.Context, s core.Source) (map[string]string, map[string]string, error) {
	if _, _, err := b.gitMirror.Sync(ctx, s); err != nil {
		return nil, nil, err
	}
	return map[string]string{}, map[string]string{}, nil
}

func TestAMirrorThatReportsNoRefsIsDoubleCheckedWithGit(t *testing.T) {
	w := newWorld(t)
	w.cfg.Mirror = blindMirror{w.mir}
	a := w.addRepo("a", core.Private)
	c1 := a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	st := mustPoll(t, r)
	if st.Scanned != 1 {
		t.Fatalf("a repo with history was recorded as empty: %+v", st)
	}
	for _, e := range w.engines {
		if c := e.callList(); len(c) != 1 || commitsOf(c[0]) != c1[:7] {
			t.Fatalf("%s: %+v", e.name, c)
		}
	}
	state, _ := loadState(w.paths.Sources, w.src("a"))
	if state.Tips["refs/heads/main"] != c1 {
		t.Fatalf("tips %v", state.Tips)
	}
}
