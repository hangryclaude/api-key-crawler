package sweep

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
	"keyguard/internal/fp"
	"keyguard/internal/triage"
)

func TestFirstPollScansEverythingAndIdlePollScansNothing(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Unverified)
	c1 := a.commit("add env", map[string]string{".env": "OPENAI_API_KEY=" + raw + "\n"})
	r := w.runner()

	st := mustPoll(t, r)
	if st.Kind != "poll" || st.Sources != 1 || st.Scanned != 1 || st.Skipped != 0 || st.NewFPs != 1 {
		t.Fatalf("first poll stats: %+v", st)
	}
	if !slices.ContainsFunc(st.Notes, func(n string) bool { return strings.Contains(n, "no inventory snapshot yet") }) {
		t.Fatalf("a first run should say it listed everything: %v", st.Notes)
	}
	for _, e := range w.engines {
		calls := e.callList()
		if len(calls) != 1 || !calls[0].rng.All || commitsOf(calls[0]) != c1[:7] {
			t.Fatalf("%s: first scan should be one full scan of the one commit: %+v", e.name, calls)
		}
		o := calls[0].opts
		if !o.Verify || o.Threads < 1 || o.Loc.Source != w.src("a") || o.Loc.Visibility != core.Private || o.Loc.Kind != "repo" {
			t.Fatalf("%s scan options: %+v", e.name, o)
		}
	}
	s := w.secret(raw)
	if !slices.Equal(s.Engines, []string{"betterleaks", "titus", "trufflehog"}) || len(s.Locations) != 1 {
		t.Fatalf("secret: engines=%v locations=%v", s.Engines, s.Locations)
	}
	if l := s.Locations[0]; l.Commit != c1 || l.Path != ".env" || l.Line != 1 || l.Source != w.src("a") {
		t.Fatalf("location: %+v", l)
	}
	if s.Triage != triage.Real || s.Severity != core.Low {
		t.Fatalf("an unverified private secret three engines agree on is real/low, got %s/%v", s.Triage, s.Severity)
	}

	w.resetCalls()
	idle := mustPoll(t, r)
	if idle.Sources != 0 || idle.Scanned != 0 || idle.Skipped != 0 || w.engineCalls() != 0 {
		t.Fatalf("a poll with nothing changed scanned something: %+v, %d engine calls", idle, w.engineCalls())
	}
	if n := w.mir.syncCount(w.src("a")); n != 1 {
		t.Fatalf("an idle poll synced the mirror again (%d syncs)", n)
	}
	if w.rep.writes != 2 {
		t.Fatalf("every run refreshes the report; wrote %d times in 2 runs", w.rep.writes)
	}
}

func TestChangedSourceWithNoNewCommitsScansNothing(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Unverified)
	a.commit("add env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	w.resetCalls()

	w.pushed("a") // GitHub says it changed (a force-push to the same tip, a tag, a settings change)
	st := mustPoll(t, r)
	if st.Sources != 1 || st.Scanned != 0 || st.Skipped != 1 || w.engineCalls() != 0 {
		t.Fatalf("stats %+v, engine calls %d: tips are unchanged, so no engine should run", st, w.engineCalls())
	}
	if n := w.mir.syncCount(w.src("a")); n != 2 {
		t.Fatalf("the changed source should have been synced once more, got %d syncs", n)
	}
	if again := mustPoll(t, r); again.Sources != 0 {
		t.Fatalf("the skipped source did not advance its inventory entry: %+v", again)
	}
}

func TestNewCommitScansOnlyThatCommit(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	raw1, raw2 := fakeKey(t, "sk-", 48), fakeKey(t, "sk-", 48)
	w.plantAll(raw1, "openai", core.Unverified)
	w.plantAll(raw2, "openai", core.Unverified)
	c1 := a.commit("one", map[string]string{".env": "A=" + raw1 + "\n"})
	r := w.runner()
	mustPoll(t, r)
	w.resetCalls()

	c2 := a.commit("two", map[string]string{"app/config.ts": "export const k = '" + raw2 + "'\n"})
	w.pushed("a")
	st := mustPoll(t, r)
	if st.Scanned != 1 || st.NewFPs != 1 {
		t.Fatalf("stats %+v", st)
	}
	for _, e := range w.engines {
		calls := e.callList()
		if len(calls) != 1 {
			t.Fatalf("%s: %d scans", e.name, len(calls))
		}
		c := calls[0]
		if c.rng.All || !slices.Equal(c.rng.Revs, []string{"--all", "--not", c1}) || c.rng.Since["refs/heads/main"] != c1 {
			t.Fatalf("%s: range %+v is not 'everything not reachable from the old tip'", e.name, c.rng)
		}
		if commitsOf(c) != c2[:7] {
			t.Fatalf("%s scanned commits %s, want only %s", e.name, commitsOf(c), c2[:7])
		}
	}
	if s := w.secret(raw2); s.Locations[0].Commit != c2 || s.Locations[0].Path != "app/config.ts" {
		t.Fatalf("new secret located at %+v", s.Locations[0])
	}
	if len(w.secret(raw1).Locations) != 1 {
		t.Fatal("re-scanning must not duplicate the first secret's location")
	}
}

func TestBranchesAndForcePushesAreCoveredByTheTipDifference(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Unverified)
	c1 := a.commit("base", map[string]string{"README": "hello\n"})
	r := w.runner()
	mustPoll(t, r)
	w.resetCalls()

	// A branch holding a commit that was never on main, then main rewritten away from c1.
	a.git("checkout", "-q", "-b", "feature")
	c2 := a.commit("oops", map[string]string{"secrets.txt": "k=" + raw + "\n"})
	a.git("checkout", "-q", "main")
	c3 := a.commit("main moves on", map[string]string{"other": "x\n"})
	a.git("reset", "-q", "--hard", c1)
	c4 := a.commit("rewritten", map[string]string{"other": "y\n"})
	w.pushed("a")
	mustPoll(t, r)
	for _, e := range w.engines {
		got := commitsOf(e.callList()[0])
		for _, want := range []string{c2[:7], c4[:7]} {
			if !strings.Contains(got, want) {
				t.Fatalf("%s did not scan %s: scanned %s", e.name, want, got)
			}
		}
		if strings.Contains(got, c1[:7]) || strings.Contains(got, c3[:7]) {
			t.Fatalf("%s rescanned a commit it had seen or one no ref reaches any more: %s", e.name, got)
		}
	}
	if len(w.secret(raw).Locations) != 1 {
		t.Fatal("secret on the feature branch was not found")
	}
}

func TestPrivateToPublicFlipRescansFullyAndEscalatesToCritical(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	raw := fakeKey(t, "sk-ant-api03-", 48)
	w.plantAll(raw, "anthropic", core.Live)
	c1 := a.commit("env", map[string]string{".env": "ANTHROPIC_API_KEY=" + raw + "\n"})
	c2 := a.commit("more", map[string]string{"x": "1\n"})
	r := w.runner()

	mustPoll(t, r)
	got := w.notif.list()
	if len(got) != 1 || got[0].sev != core.High || !strings.Contains(got[0].title, "HIGH") {
		t.Fatalf("a live key in a private repo should alert once at high: %+v", got)
	}
	if s := w.secret(raw); s.Severity != core.High || s.Notified != core.High {
		t.Fatalf("after the first poll: severity %v notified %v", s.Severity, s.Notified)
	}
	w.resetCalls()

	w.inv.edit(w.src("a"), func(s *core.Source) { s.Visibility = core.Public }) // pushedAt does not move
	st := mustPoll(t, r)
	if st.Scanned != 1 {
		t.Fatalf("the flipped repo was not scanned: %+v", st)
	}
	for _, e := range w.engines {
		calls := e.callList()
		if len(calls) != 1 || !calls[0].rng.All || !slices.Equal(calls[0].commits, []string{c1, c2}) {
			t.Fatalf("%s: a flip to public must rescan the whole history, got %+v", e.name, calls)
		}
		if calls[0].opts.Loc.Visibility != core.Public {
			t.Fatalf("%s scanned with visibility %s", e.name, calls[0].opts.Loc.Visibility)
		}
	}
	if !slices.ContainsFunc(st.Notes, func(n string) bool { return strings.Contains(n, "went from private to public") }) {
		t.Fatalf("the flip should be in the notes: %v", st.Notes)
	}
	got = w.notif.list()
	if len(got) != 2 {
		t.Fatalf("want a second, critical alert, got %d: %+v", len(got), got)
	}
	if n := got[1]; n.sev != core.Critical || !strings.Contains(n.title, "ESCALATED") || !strings.Contains(n.title, "CRITICAL") {
		t.Fatalf("escalation alert: %+v", n)
	}
	if s := w.secret(raw); s.Severity != core.Critical || s.Notified != core.Critical || !s.Exposed() {
		t.Fatalf("after the flip: severity %v notified %v", s.Severity, s.Notified)
	}

	mustPoll(t, r)
	if w.notif.count() != 2 {
		t.Fatalf("a quiet poll repeated the alert: %d notices", w.notif.count())
	}
}

// The alert about a repo going public must not wait for its rescan to succeed: the key is
// exposed whether or not the mirror could be fetched.
func TestFlipAlertsEvenWhenTheRescanFails(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	if w.notif.count() != 1 {
		t.Fatalf("setup: %d notices", w.notif.count())
	}

	w.inv.edit(w.src("a"), func(s *core.Source) { s.Visibility = core.Public })
	w.mir.fail[w.src("a")] = errors.New("fetch: remote hung up")
	st := mustPoll(t, r)
	if !hasNote(st, "mirror sync failed") || st.Scanned != 0 {
		t.Fatalf("%+v", st)
	}
	n := w.notif.list()
	if len(n) != 2 || n[1].sev != core.Critical || !strings.Contains(n[1].title, "ESCALATED") {
		t.Fatalf("the flip must alert from the stored locations alone: %+v", n)
	}

	// The failed source is still 'changed', so the next poll does the full rescan, quietly.
	delete(w.mir.fail, w.src("a"))
	w.resetCalls()
	st = mustPoll(t, r)
	for _, e := range w.engines {
		if c := e.callList(); len(c) != 1 || !c[0].rng.All {
			t.Fatalf("%s: the rescan after the flip was lost: %+v", e.name, c)
		}
	}
	if w.notif.count() != 2 {
		t.Fatalf("the rescan repeated the alert: %d notices", w.notif.count())
	}
}

func TestFlipDoesNotRescanWhenExposureDecreasesOrStaysTheSame(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	a.commit("base", map[string]string{"README": "x\n"})
	r := w.runner()
	mustPoll(t, r)
	w.resetCalls()
	w.inv.edit(w.src("a"), func(s *core.Source) { s.Visibility = core.Private })
	st := mustPoll(t, r)
	if w.engineCalls() != 0 || st.Skipped != 1 {
		t.Fatalf("going private needs no rescan: %+v, %d calls", st, w.engineCalls())
	}
	w.inv.edit(w.src("a"), func(s *core.Source) { s.Visibility = core.SecretGist })
	mustPoll(t, r) // private -> a secret gist is an increase
	if w.engineCalls() == 0 {
		t.Fatal("private to secret-gist is more exposure and must rescan")
	}
}

func TestThreeEnginesTwoReposOneValueIsOneSecretWithTwoLocations(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	b := w.addRepo("b", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Unverified)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	b.commit("env", map[string]string{"cfg/.env": "OTHER=1\nK=" + raw + "\n"})
	r := w.runner()
	st := mustPoll(t, r)
	if st.Scanned != 2 || st.NewFPs != 1 {
		t.Fatalf("stats %+v", st)
	}
	all := w.store.Secrets()
	if len(all) != 1 {
		t.Fatalf("%d secrets, want 1", len(all))
	}
	s := all[0]
	if len(s.Locations) != 2 || len(s.Engines) != 3 {
		t.Fatalf("locations=%d engines=%v", len(s.Locations), s.Engines)
	}
	srcs := []string{s.Locations[0].Source, s.Locations[1].Source}
	slices.Sort(srcs)
	if srcs[0] != w.src("a") || srcs[1] != w.src("b") {
		t.Fatalf("locations are in %v", srcs)
	}
	if !s.Exposed() || s.Severity != core.Medium {
		t.Fatalf("real, unverified and public in one place should be medium, got %v", s.Severity)
	}
}

// One key committed to thirty repos, scanned by eight workers with three engines each: one
// secret, thirty places, and the alerts stay at one per severity step however the workers
// interleave.
func TestOneKeyInManyReposUnderConcurrency(t *testing.T) {
	w := newWorld(t)
	w.cfg.Jobs = 8
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	for i := 0; i < 30; i++ {
		vis := core.Private
		if i%2 == 0 {
			vis = core.Public
		}
		w.addRepo(fmt.Sprintf("r%02d", i), vis).commit("env", map[string]string{".env": "K=" + raw + "\n"})
	}
	r := w.runner()
	st := mustPoll(t, r)
	if st.Scanned != 30 || st.NewFPs != 1 {
		t.Fatalf("%+v", st)
	}
	all := w.store.Secrets()
	if len(all) != 1 || len(all[0].Locations) != 30 || len(all[0].Engines) != 3 {
		t.Fatalf("%d secrets, locations=%d engines=%v", len(all), len(all[0].Locations), all[0].Engines)
	}
	s := all[0]
	if s.Severity != core.Critical || s.Notified != core.Critical {
		t.Fatalf("severity %v notified %v", s.Severity, s.Notified)
	}
	if n := w.notif.list(); len(n) < 1 || len(n) > 2 {
		t.Fatalf("%d alerts for one key: one for each severity it passed through, no more", len(n))
	} else if last := n[len(n)-1]; last.sev != core.Critical {
		t.Fatalf("the last alert should be the critical one: %+v", last)
	}
	// A second full pass over all of it finds the same thirty places and alerts no more.
	alerts := w.notif.count()
	mustFull(t, r)
	if again := w.store.Secrets(); len(again) != 1 || len(again[0].Locations) != 30 || w.notif.count() != alerts {
		t.Fatalf("a repeat scan changed things: %d secrets, %d locations, %d alerts (was %d)", len(again), len(again[0].Locations), w.notif.count(), alerts)
	}
}

func TestVerifiedDeadLaterResolvesTheSecret(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	s := w.secret(raw)
	if s.Verified != core.Live || s.Status != db.StatusOpen || s.Severity != core.Critical {
		t.Fatalf("live: %s %s %v", s.Verified, s.Status, s.Severity)
	}
	if w.notif.count() != 1 {
		t.Fatalf("%d notices", w.notif.count())
	}

	w.plantAll(raw, "openai", core.Dead) // the key was rotated
	mustFull(t, r)
	s = w.secret(raw)
	if s.Verified != core.Dead || s.Status != db.StatusResolved || s.Severity != core.Info {
		t.Fatalf("after rotation: %s %s %v", s.Verified, s.Status, s.Severity)
	}
	if w.notif.count() != 1 {
		t.Fatalf("a rotated key must not alert again: %d notices", w.notif.count())
	}

	// A later scan with verification off reports unverified: that must not resurrect it.
	for _, e := range w.engines {
		e.plantValue(raw, "openai", core.Unverified)
	}
	mustFull(t, r)
	if s := w.secret(raw); s.Verified != core.Dead || s.Status != db.StatusResolved {
		t.Fatalf("an unverified sighting reopened a dead key: %s %s", s.Verified, s.Status)
	}
}

// Timestamps have one-second resolution, and a rotated key can be re-checked within the
// second the live verdict was recorded. The later run must still win.
func TestARotationInTheSameSecondStillResolves(t *testing.T) {
	w := newWorld(t)
	w.cfg.Now = func() time.Time { return time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC) }
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	w.plantAll(raw, "openai", core.Dead)
	mustFull(t, r)
	if s := w.secret(raw); s.Verified != core.Dead || s.Status != db.StatusResolved || s.Severity != core.Info {
		t.Fatalf("%s %s %v", s.Verified, s.Status, s.Severity)
	}
}

func TestIgnoreIsHonoredAndSurvivesLosingTheFindings(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	if w.notif.count() != 1 {
		t.Fatalf("setup: %d notices", w.notif.count())
	}
	if err := w.store.Ignore(fp.ID(w.kr.FP(raw)), "fixture on purpose"); err != nil {
		t.Fatal(err)
	}

	a.commit("again", map[string]string{"copy.env": "K=" + raw + "\n"})
	w.pushed("a")
	st := mustPoll(t, r)
	s := w.secret(raw)
	if s.Status != db.StatusIgnored || s.Severity != core.Info || len(s.Locations) != 2 {
		t.Fatalf("ignored secret: %s %v, %d locations", s.Status, s.Severity, len(s.Locations))
	}
	if st.NewFPs != 0 || w.notif.count() != 1 {
		t.Fatalf("an ignored secret caused new work: %+v, %d notices", st, w.notif.count())
	}

	// Lose the findings file. The ignore list is separate and must be enough.
	if err := os.Rename(w.paths.Findings, w.paths.Findings+".gone"); err != nil {
		t.Fatal(err)
	}
	fresh, err := db.Open(w.paths)
	if err != nil {
		t.Fatal(err)
	}
	notif := &fakeNotifier{}
	cfg := w.cfg
	cfg.Store, cfg.Notifier = fresh, notif
	cfg.Triage = triage.New(triage.WithStoreEvidence(fresh), triage.WithFingerprinter(w.kr))
	r2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	st = mustFull(t, r2)
	s, ok := fresh.Get(w.kr.FP(raw))
	if !ok || s.Status != db.StatusIgnored || s.Severity != core.Info {
		t.Fatalf("rebuilt store forgot the ignore: %+v", s)
	}
	if notif.count() != 0 || st.NewFPs != 0 {
		t.Fatalf("an ignored secret alerted after the findings were rebuilt: %d notices, %+v", notif.count(), st)
	}
}

func TestSecondConcurrentRunIsBlockedByTheLock(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("x", map[string]string{"f": "1\n"})
	gate := make(chan struct{})
	entered := make(chan struct{}, 16)
	for _, e := range w.engines {
		e.set(func(e *gitEngine) { e.gate, e.entered = gate, entered })
	}
	r1, r2 := w.runner(), w.runner()
	type result struct {
		st  core.RunStats
		err error
	}
	done := make(chan result)
	go func() {
		st, err := r1.Poll(context.Background())
		done <- result{st, err}
	}()
	<-entered // an engine is inside its scan, so the first run holds the lock

	st, err := r2.Poll(context.Background())
	if !errors.Is(err, ErrLocked) || !errors.Is(err, db.ErrLocked) {
		t.Fatalf("second concurrent poll: %v", err)
	}
	var le *db.LockedError
	if !errors.As(err, &le) || le.PID == 0 {
		t.Fatalf("the error should name the holder: %v", err)
	}
	if st.Kind != "poll" || st.Finished == "" {
		t.Fatalf("blocked run stats: %+v", st)
	}
	if _, ferr := r2.Full(context.Background()); !errors.Is(ferr, ErrLocked) {
		t.Fatalf("full while polling: %v", ferr)
	}
	close(gate)
	if res := <-done; res.err != nil {
		t.Fatalf("first run: %v", res.err)
	}
	if _, err := os.Stat(w.paths.Lock); !os.IsNotExist(err) {
		t.Fatalf("the lock outlived its run: %v", err)
	}
	runs, _ := os.ReadDir(w.paths.Runs)
	if len(runs) != 1 {
		t.Fatalf("a blocked attempt is not a run and must not write stats; found %d run files", len(runs))
	}
	mustPoll(t, r2) // free again
}

func TestEngineVersionChangeRescansOnlyThatEngineInFull(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Unverified)
	c1 := a.commit("one", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	c2 := a.commit("two", map[string]string{"y": "2\n"})
	w.pushed("a")
	w.resetCalls()

	w.engines[1].set(func(e *gitEngine) { e.ver = "2.0.0" }) // trufflehog upgraded
	mustPoll(t, r)
	for i, e := range w.engines {
		c := e.callList()
		if len(c) != 1 {
			t.Fatalf("%s: %d scans", e.name, len(c))
		}
		if i == 1 {
			if !c[0].rng.All || !slices.Equal(c[0].commits, []string{c1, c2}) {
				t.Fatalf("%s upgraded and must rescan everything: %+v", e.name, c[0])
			}
		} else if c[0].rng.All || commitsOf(c[0]) != c2[:7] {
			t.Fatalf("%s did not change and must scan only the new commit: %+v", e.name, c[0])
		}
	}
	w.resetCalls()
	w.pushed("a")
	mustPoll(t, r)
	if w.engineCalls() != 0 {
		t.Fatal("after the upgrade scan nothing is due")
	}
}

func TestEngineFailureKeepsItsBacklogAndOthersMoveOn(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	c2 := a.commit("two", map[string]string{"g": "2\n"})
	w.pushed("a")
	w.resetCalls()

	titus := w.engines[2]
	titus.set(func(e *gitEngine) { e.err = errors.New("titus crashed on a blob") })
	st, err := r.Poll(context.Background())
	if err != nil {
		t.Fatalf("one engine failing is a note, not a failed run: %v", err)
	}
	if !slices.ContainsFunc(st.Notes, func(n string) bool { return strings.Contains(n, "titus failed") }) {
		t.Fatalf("notes: %v", st.Notes)
	}
	if e := st.Engines["titus"]; e.Errors != 1 {
		t.Fatalf("titus stats: %+v", e)
	}
	if st.Engines["betterleaks"].Errors != 0 {
		t.Fatalf("betterleaks stats: %+v", st.Engines["betterleaks"])
	}
	state, _ := loadState(w.paths.Sources, w.src("a"))
	if state == nil || state.ScannedWith["titus"] == "" || len(state.Lag["titus"]) == 0 || len(state.Lag["betterleaks"]) != 0 {
		t.Fatalf("state should show titus lagging only: %+v", state)
	}

	w.resetCalls()
	titus.set(func(e *gitEngine) { e.err = nil })
	st = mustPoll(t, r) // the snapshot did not advance, so the source comes back
	if st.Scanned != 1 {
		t.Fatalf("the failed source was not retried: %+v", st)
	}
	for _, e := range w.engines[:2] {
		if len(e.callList()) != 0 {
			t.Fatalf("%s already finished this commit and must not rescan it", e.name)
		}
	}
	calls := titus.callList()
	if len(calls) != 1 || calls[0].rng.All || commitsOf(calls[0]) != c2[:7] {
		t.Fatalf("titus should retry only its backlog: %+v", calls)
	}
	w.pushed("a")
	if mustPoll(t, r); w.engineCalls() != 1 {
		t.Fatal("everything is caught up after the retry")
	}
}

// Fresh is how to ask for what Full used to do: every engine over every commit, whatever the
// state or the ledger says. (Full with a warm ledger is ledger_test.go's business.)
func TestFullIgnoresStateAndScansEveryEngineFromTheStart(t *testing.T) {
	w := newWorld(t)
	w.cfg.Fresh = true
	a := w.addRepo("a", core.Private)
	b := w.addRepo("b", core.Private)
	c1 := a.commit("one", map[string]string{"f": "1\n"})
	c2 := a.commit("two", map[string]string{"f": "2\n"})
	b1 := b.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	w.resetCalls()

	st := mustFull(t, r)
	if st.Kind != "full" || st.Sources != 2 || st.Scanned != 2 {
		t.Fatalf("%+v", st)
	}
	for _, e := range w.engines {
		calls := e.callList()
		if len(calls) != 2 {
			t.Fatalf("%s: %d scans, want one per source", e.name, len(calls))
		}
		for _, c := range calls {
			if !c.rng.All {
				t.Fatalf("%s: a full run must scan everything: %+v", e.name, c.rng)
			}
			want := []string{c1, c2}
			if strings.HasSuffix(c.repo, "o__b.git") {
				want = []string{b1}
			}
			if !slices.Equal(c.commits, want) {
				t.Fatalf("%s scanned %v in %s", e.name, shortAll(c.commits), c.repo)
			}
		}
	}
	deep, err := r.Deep(context.Background())
	if err != nil || deep.Kind != "deep" {
		t.Fatalf("deep: %+v %v", deep, err)
	}
}

func TestSourceStateAndSnapshotFiles(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	c1 := a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)

	path := filepath.Join(w.paths.Sources, "github.com__o__a.json")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state mode %v", fi.Mode().Perm())
	}
	var raw map[string]any
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"source", "visibility", "tips", "scanned_with", "last_scan"} {
		if _, ok := raw[k]; !ok {
			t.Fatalf("state file lacks %q: %s", k, b)
		}
	}
	if _, ok := raw["lag"]; ok {
		t.Fatalf("a source with every engine caught up has no lag: %s", b)
	}
	tips := raw["tips"].(map[string]any)
	if tips["refs/heads/main"] != c1 {
		t.Fatalf("tips %v", tips)
	}
	sw := raw["scanned_with"].(map[string]any)
	if len(sw) != 3 || sw["betterleaks"] != "1.0.0" {
		t.Fatalf("scanned_with %v", sw)
	}

	// The inventory snapshot uses the layout inventory.SaveSnapshot writes.
	var snap struct {
		Version int           `json:"version"`
		Updated string        `json:"updated"`
		Sources []core.Source `json:"sources"`
	}
	b, err = os.ReadFile(w.paths.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &snap); err != nil || snap.Version != 1 || snap.Updated == "" || len(snap.Sources) != 1 || snap.Sources[0].ID != w.src("a") {
		t.Fatalf("snapshot: %v %+v", err, snap)
	}
	if fi, _ := os.Stat(w.paths.Inventory); fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode %v", fi.Mode().Perm())
	}
}

func TestStateFileOfAnotherSourceOrCorruptMeansRescan(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	path := filepath.Join(w.paths.Sources, "github.com__o__a.json")

	for name, body := range map[string]string{
		"corrupt":       "{not json",
		"other source":  `{"source":"github.com/o/other","tips":{},"scanned_with":{}}`,
		"empty object":  `{}`,
		"wrong version": `{"source":"github.com/o/a","tips":{"refs/heads/main":"` + strings.Repeat("0", 40) + `"},"scanned_with":{"betterleaks":"0.0.1","trufflehog":"0.0.1","titus":"0.0.1"}}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if name == "wrong version" {
			// A record made by other versions is only a reason to rescan if the engines are other
			// versions too: the ledger knows what the current ones have read, and says so.
			for _, e := range w.engines {
				e.set(func(e *gitEngine) { e.ver = "2.0.0" })
			}
		}
		w.pushed("a")
		w.resetCalls()
		st := mustPoll(t, r)
		if st.Scanned != 1 {
			t.Fatalf("%s: not rescanned: %+v", name, st)
		}
		for _, e := range w.engines {
			if c := e.callList(); len(c) != 1 || !c[0].rng.All {
				t.Fatalf("%s: %s should have scanned everything: %+v", name, e.name, c)
			}
		}
	}
}

func TestRunStatsAreWrittenAndParse(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Unverified)
	a.commit("one", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	mustPoll(t, r)
	mustFull(t, r)

	ents, err := os.ReadDir(w.paths.Runs)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 3 {
		t.Fatalf("3 runs left %d files", len(ents))
	}
	var kinds []string
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(w.paths.Runs, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var st core.RunStats
		if err := json.Unmarshal(b, &st); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if st.Started == "" || st.Finished < st.Started || len(st.Engines) == 0 && st.Scanned > 0 {
			t.Fatalf("%s: %+v", e.Name(), st)
		}
		if fi, _ := e.Info(); fi.Mode().Perm() != 0o600 || !strings.HasSuffix(e.Name(), ".json") {
			t.Fatalf("%s mode %v", e.Name(), fi.Mode().Perm())
		}
		if st.Scanned > 0 {
			for _, eng := range []string{"betterleaks", "trufflehog", "titus"} {
				if es, ok := st.Engines[eng]; !ok || es.Hits != 1 || es.Seconds < 0 {
					t.Fatalf("%s: engine %s stats %+v", e.Name(), eng, es)
				}
			}
		}
		kinds = append(kinds, st.Kind)
	}
	slices.Sort(kinds)
	if !slices.Equal(kinds, []string{"full", "poll", "poll"}) {
		t.Fatalf("kinds %v", kinds)
	}
}

func TestRunsInTheSameMomentDoNotOverwriteEachOther(t *testing.T) {
	w := newWorld(t)
	w.cfg.Now = func() time.Time { return time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC) } // a clock that never moves
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	mustPoll(t, r)
	mustPoll(t, r)
	ents, _ := os.ReadDir(w.paths.Runs)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if len(names) != 3 {
		t.Fatalf("three runs in one instant left %v", names)
	}
}

func TestNoVerifyTurnsVerificationOffAndDefaultIsOn(t *testing.T) {
	for _, noVerify := range []bool{false, true} {
		w := newWorld(t)
		w.cfg.NoVerify = noVerify
		a := w.addRepo("a", core.Public)
		raw := fakeKey(t, "sk-", 48)
		w.plantAll(raw, "openai", core.Live)
		a.commit("one", map[string]string{".env": "K=" + raw + "\n"})
		mustPoll(t, w.runner())
		for _, e := range w.engines {
			if got := e.callList()[0].opts.Verify; got == noVerify {
				t.Fatalf("NoVerify=%v but Verify=%v", noVerify, got)
			}
		}
		wantVerified := core.Live
		if noVerify {
			wantVerified = core.Unverified
		}
		if v := w.secret(raw).Verified; v != wantVerified {
			t.Fatalf("NoVerify=%v: verified=%s", noVerify, v)
		}
	}
}

func TestRulesAndThreadsReachTheEngines(t *testing.T) {
	w := newWorld(t)
	w.cfg.Rules = "/some/rules/keyguard.toml"
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	mustPoll(t, w.runner())
	if o := w.engines[0].callList()[0].opts; o.Rules != "/some/rules/keyguard.toml" || o.Threads < 1 {
		t.Fatalf("%+v", o)
	}
}

func TestContextEvidenceFromTheStoreReachesTriage(t *testing.T) {
	w := newWorld(t)
	w.cfg.NoVerify = true // found with verification off: the engine says nothing about the key
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "", 40)
	w.engines[0].plantValue(raw, "generic", core.Live)
	a.commit("page", map[string]string{"web/form.html": `<div class="g-recaptcha" data-sitekey="` + raw + `"></div>` + "\n"})
	r := w.runner()
	mustPoll(t, r)
	s := w.secret(raw)
	if s.Triage != triage.PublicByDesign || s.Severity != core.Info || !strings.Contains(s.TriageWhy, "reCAPTCHA") {
		t.Fatalf("the line a key sits on is stored and read by triage: %s / %v / %q", s.Triage, s.Severity, s.TriageWhy)
	}
	if w.notif.count() != 0 {
		t.Fatal("a public site key alerted")
	}

	// Verification is on now. The provider says it is live, which overrides the label and the
	// alert fires: the ledger of an engine that did not verify is not the ledger of one that does.
	w.cfg.NoVerify = false
	mustFull(t, w.runner())
	s = w.secret(raw)
	if s.Triage != triage.Real || s.Severity != core.Critical || !strings.Contains(s.TriageWhy, "overrides the public-by-design label") {
		t.Fatalf("%s / %v / %q", s.Triage, s.Severity, s.TriageWhy)
	}
	if w.notif.count() != 1 {
		t.Fatalf("%d notices", w.notif.count())
	}
}

func TestEverythingSurvivesARestart(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	mustPoll(t, w.runner())
	before := w.store.Secrets()

	// A new process: the store, the triager and the runner are rebuilt from disk.
	store2, err := db.Open(w.paths)
	if err != nil {
		t.Fatal(err)
	}
	cfg := w.cfg
	cfg.Store = store2
	cfg.Triage = triage.New(triage.WithStoreEvidence(store2), triage.WithFingerprinter(w.kr))
	r2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(before) != fmt.Sprint(store2.Secrets()) {
		t.Fatal("the reloaded store differs")
	}
	w.resetCalls()
	st := mustPoll(t, r2)
	if st.Sources != 0 || w.engineCalls() != 0 || w.notif.count() != 1 {
		t.Fatalf("a restart caused work or a repeat alert: %+v, %d scans, %d notices", st, w.engineCalls(), w.notif.count())
	}
	c2 := a.commit("later", map[string]string{"x": "1\n"})
	w.pushed("a")
	mustPoll(t, r2)
	for _, e := range w.engines {
		if c := e.callList(); len(c) != 1 || c[0].rng.All || commitsOf(c[0]) != c2[:7] {
			t.Fatalf("%s after restart: %+v", e.name, c)
		}
	}
}
