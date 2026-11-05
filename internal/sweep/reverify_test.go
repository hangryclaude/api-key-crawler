package sweep

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/db"
)

func TestNeedsRefresh(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	cases := []struct {
		name string
		s    core.Secret
		all  bool
		want bool
	}{
		{"live, fresh", core.Secret{Verified: core.Live, VerifiedAt: at(-time.Hour)}, false, false},
		{"live, past six hours", core.Secret{Verified: core.Live, VerifiedAt: at(-6*time.Hour - time.Second)}, false, true},
		{"live, fresh, on a full run", core.Secret{Verified: core.Live, VerifiedAt: at(-time.Minute)}, true, true},
		{"live with no date is nobody's verdict", core.Secret{Verified: core.Live}, false, true},
		{"live, the schedule says later", core.Secret{Verified: core.Live, VerifiedAt: at(-7 * time.Hour), NextVerifyAt: at(time.Hour)}, false, false},
		{"live, the schedule says now", core.Secret{Verified: core.Live, VerifiedAt: at(-time.Hour), NextVerifyAt: at(-time.Second)}, false, true},
		{"dead, fresh", core.Secret{Verified: core.Dead, VerifiedAt: at(-24 * time.Hour)}, false, false},
		{"dead, fresh, on a full run", core.Secret{Verified: core.Dead, VerifiedAt: at(-24 * time.Hour)}, true, false},
		{"dead, past a week", core.Secret{Verified: core.Dead, VerifiedAt: at(-8 * 24 * time.Hour)}, false, true},
		{"undecided, waiting out its backoff", core.Secret{Verified: core.VerifyError, NextVerifyAt: at(time.Minute)}, false, false},
		{"undecided, its time has come", core.Secret{Verified: core.VerifyError, NextVerifyAt: at(-time.Minute)}, false, true},
		{"undecided with no schedule waits for a full run", core.Secret{Verified: core.VerifyError}, false, false},
		{"undecided with no schedule, on a full run", core.Secret{Verified: core.VerifyError}, true, true},
		{"unverified is never asked about", core.Secret{Verified: core.Unverified}, true, false},
		{"ignored is never asked about", core.Secret{Verified: core.Live, VerifiedAt: at(-24 * time.Hour), Status: core.StatusIgnored}, true, false},
	}
	for _, c := range cases {
		if got := needsRefresh(c.s, now, c.all); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAnAgedLiveVerdictIsAskedAboutAgainByReadingOnlyItsCommit(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	c1 := a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	a.commit("later", map[string]string{"x": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	if s := w.secret(raw); s.Verified != core.Live || s.Severity != core.Critical {
		t.Fatalf("setup: %+v", s)
	}

	w.plantAll(raw, "openai", core.Dead) // rotated since
	w.resetCalls()
	if mustPoll(t, r); w.engineCalls() != 0 {
		t.Fatal("the verdict is minutes old and nothing was pushed: nothing to read")
	}

	w.clock.advance(core.LiveTTL + time.Minute)
	st := mustPoll(t, r)
	for _, e := range w.engines {
		c := e.callList()
		if len(c) != 1 || c[0].rng.All || len(c[0].rng.Revs) != 1 || c[0].rng.Revs[0] != c1+"^!" || !c[0].opts.Verify {
			t.Fatalf("%s should re-read the one commit that holds the key, with verification: %+v", e.name, c)
		}
		if len(c[0].commits) != 1 || c[0].commits[0] != c1 {
			t.Fatalf("%s read %v", e.name, shortAll(c[0].commits))
		}
	}
	s := w.secret(raw)
	if s.Verified != core.Dead || s.Status != db.StatusResolved || s.Severity != core.Info {
		t.Fatalf("a rotated key is resolved by the refresh: %s %s %v", s.Verified, s.Status, s.Severity)
	}
	if !hasNote(st, "re-verified 1 key(s) by reading 1 commit(s) in 1 source(s)") {
		t.Fatalf("%v", st.Notes)
	}

	w.resetCalls()
	w.clock.advance(time.Hour)
	if mustPoll(t, r); w.engineCalls() != 0 {
		t.Fatal("a fresh verdict is left alone")
	}
}

func TestAFullRunReVerifiesEveryLiveKeyAndNothingElse(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	live, dead, plain := fakeKey(t, "sk-", 48), fakeKey(t, "sk-", 48), fakeKey(t, "sk-", 48)
	w.plantAll(live, "openai", core.Live)
	w.plantAll(dead, "openai", core.Dead)
	w.plantAll(plain, "openai", core.Unverified)
	cLive := a.commit("live", map[string]string{"live": live + "\n"})
	a.commit("dead", map[string]string{"dead": dead + "\n"})
	a.commit("plain", map[string]string{"plain": plain + "\n"})
	r := w.runner()
	mustPoll(t, r)
	w.resetCalls()
	mustFull(t, r)
	for _, e := range w.engines {
		c := e.callList()
		if len(c) != 1 || len(c[0].rng.Revs) != 1 || c[0].rng.Revs[0] != cLive+"^!" {
			t.Fatalf("%s: a full run asks about live keys only (dead ones have a week, and an unverified one has no verifier or was found with verification off): %+v", e.name, c)
		}
	}
}

func TestReVerificationWorksForKeysInWikisToo(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	a.commit("one", map[string]string{"f": "1\n"})
	wiki := newRepo(t, t.TempDir()+"/a.wiki")
	w.mir.origins["github.com/o/a.wiki"] = wiki.dir
	w.inv.list = append(w.inv.list, core.Source{ID: "github.com/o/a.wiki", Kind: "wiki", Owner: "o", Name: "a.wiki", Account: "o", Visibility: core.Public, PushedAt: w.pushedAt()})
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	cw := wiki.commit("Setup", map[string]string{"Setup.md": "key " + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	w.plantAll(raw, "openai", core.Dead)
	w.resetCalls()
	w.clock.advance(core.LiveTTL + time.Minute)
	mustPoll(t, r)
	for _, e := range w.engines {
		c := e.callList()
		if len(c) != 1 || c[0].commits[0] != cw {
			t.Fatalf("%s: %+v", e.name, c)
		}
	}
	if s := w.secret(raw); s.Verified != core.Dead {
		t.Fatal("the wiki key was not re-verified")
	}
}

func TestNoVerifyMeansNothingIsReVerified(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	w.cfg.NoVerify = true
	r = w.runner()
	w.clock.advance(core.LiveTTL + time.Minute)
	w.resetCalls()
	mustPoll(t, r)
	mustFull(t, r) // the engines read the history again here, without verification: a ledger of their own
	for _, e := range w.engines {
		for _, c := range e.callList() {
			if len(c.rng.Revs) > 0 && strings.HasSuffix(c.rng.Revs[0], "^!") || c.opts.Verify {
				t.Fatalf("%s: verification is off, so there is nothing to re-verify: %+v", e.name, c)
			}
		}
	}
}

func TestKeysThatSitNowhereTheSweepCanReadAreSaidOutLoud(t *testing.T) {
	w := newWorld(t)
	w.cfg.ExposedOnly = true
	a := w.addRepo("a", core.Public)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	// A live key found in a repo that has gone private since, and one whose commit is gone.
	priv := w.addRepo("closed", core.Private)
	priv.commit("one", map[string]string{"f": "1\n"})
	for name, loc := range map[string]core.Location{
		"private": {Source: w.src("closed"), Kind: "repo", Visibility: core.Private, Commit: "1111111111111111111111111111111111111111"},
		"comment": {Source: w.src("a"), Kind: "comment", Visibility: core.Public, URL: "https://github.com/o/a/issues/1"},
	} {
		raw := fakeKey(t, "sk-", 48)
		err := w.store.Put(core.Secret{
			FP: w.kr.FP(raw), ID: "kg" + name[:3] + "000", Type: "openai", Verified: core.Live, VerifiedAt: "2026-11-02T00:00:00Z",
			Triage: "real", Status: db.StatusOpen, Locations: []core.Location{loc},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	w.resetCalls()
	w.clock.advance(core.LiveTTL + time.Hour)
	if st := mustPoll(t, r); hasNote(st, "sit nowhere the sweep can re-read") || w.engineCalls() != 0 {
		t.Fatalf("a poll would say this every ten minutes: %v", st.Notes)
	}
	st := mustFull(t, r)
	if !hasNote(st, "2 key(s) are due for re-verification but sit nowhere the sweep can re-read") || w.engineCalls() != 0 {
		t.Fatalf("%v, %d engine runs", st.Notes, w.engineCalls())
	}
}

func TestACommitGoneFromTheMirrorIsSaidAndOthersAreStillRead(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	c1 := a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	// The same secret also seen in a commit the mirror no longer has (a force-push).
	s := w.secret(raw)
	s.Locations = append(s.Locations, core.Location{Source: w.src("a"), Kind: "repo", Visibility: core.Public, Commit: "2222222222222222222222222222222222222222", Path: "old"})
	if err := w.store.Put(s); err != nil {
		t.Fatal(err)
	}
	w.plantAll(raw, "openai", core.Dead)
	w.resetCalls()
	w.clock.advance(core.LiveTTL + time.Hour)
	st := mustPoll(t, r)
	if !hasNote(st, "1 commit(s) holding keys due for re-verification are no longer in the mirror") {
		t.Fatalf("%v", st.Notes)
	}
	if c := w.engines[0].callList(); len(c) != 1 || c[0].commits[0] != c1 {
		t.Fatalf("%+v", c)
	}
	if w.secret(raw).Verified != core.Dead {
		t.Fatal("the commit that is still there was not re-read")
	}
}

func TestAnEngineThatFailsWhileReVerifyingIsANoteAndTheKeyStaysDue(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Live)
	a.commit("env", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	mustPoll(t, r)
	w.clock.advance(core.LiveTTL + time.Hour)
	for _, e := range w.engines {
		e.set(func(e *gitEngine) { e.err = errors.New("provider unreachable") })
	}
	st, err := r.Poll(context.Background())
	if err != nil {
		t.Fatalf("a failed re-check is a note, not a failed run: %v", err)
	}
	if !hasNote(st, "failed while re-verifying: provider unreachable") {
		t.Fatalf("%v", st.Notes)
	}
	if s := w.secret(raw); s.Verified != core.Live {
		t.Fatalf("an engine that could not answer says nothing about the key: %+v", s)
	}
	for _, e := range w.engines {
		e.set(func(e *gitEngine) { e.err = nil })
	}
	w.resetCalls()
	mustPoll(t, r)
	if w.engineCalls() == 0 {
		t.Fatal("the verdict is still old, so the key is still due")
	}
}

// "a^! b^!" is not the two commits a and b when one is the other's parent, so the refresh asks
// for one commit at a time.
func TestReVerificationReadsEachCommitInItsOwnCall(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	k1, k2 := fakeKey(t, "sk-", 48), fakeKey(t, "sk-", 48)
	w.plantAll(k1, "openai", core.Live)
	w.plantAll(k2, "openai", core.Live)
	c1 := a.commit("first", map[string]string{"one.env": "K=" + k1 + "\n"})
	c2 := a.commit("second", map[string]string{"two.env": "K=" + k2 + "\n"}) // c1 is c2's parent
	if both := strings.Fields(a.git("rev-list", c1+"^!", c2+"^!")); len(both) != 1 || both[0] != c2 {
		t.Fatalf("setup: git itself drops the older of two adjacent commits from a^! b^!: %v", both)
	}
	r := w.runner()
	mustPoll(t, r)
	w.plantAll(k1, "openai", core.Dead)
	w.plantAll(k2, "openai", core.Dead)
	w.resetCalls()
	w.clock.advance(core.LiveTTL + time.Minute)
	mustPoll(t, r)
	for _, e := range w.engines {
		seen := map[string]bool{}
		for _, c := range e.callList() {
			if len(c.rng.Revs) != 1 || len(c.commits) != 1 {
				t.Fatalf("%s: each call names one commit: %+v", e.name, c.rng)
			}
			seen[c.commits[0]] = true
		}
		if !seen[c1] || !seen[c2] {
			t.Fatalf("%s did not read both commits: %v", e.name, seen)
		}
	}
	if w.secret(k1).Verified != core.Dead || w.secret(k2).Verified != core.Dead {
		t.Fatal("both keys should have been re-verified")
	}
}

func TestPastThirtyTwoCommitsTheRefreshReadsTheWholeHistory(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	for i := 0; i <= refreshMaxCommits; i++ {
		k := fakeKey(t, "sk-", 48)
		w.plantAll(k, "openai", core.Live)
		a.commit("k", map[string]string{"f" + strconv.Itoa(i): "K=" + k + "\n"})
	}
	r := w.runner()
	mustPoll(t, r)
	w.resetCalls()
	w.clock.advance(core.LiveTTL + time.Minute)
	st := mustPoll(t, r)
	if !hasNote(st, "too many to read one at a time") {
		t.Fatalf("%v", st.Notes)
	}
	for _, e := range w.engines {
		if c := e.callList(); len(c) != 1 || !c[0].rng.All {
			t.Fatalf("%s: %d calls, first %+v", e.name, len(c), c)
		}
	}
}
