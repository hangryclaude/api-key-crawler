package sweep

import (
	"context"
	"slices"
	"strings"
	"testing"

	"keyguard/internal/core"
)

func noteMatching(st core.RunStats, sub string) bool {
	return slices.ContainsFunc(st.Notes, func(n string) bool { return strings.Contains(n, sub) })
}

func TestExposedOnlyNeverFetchesAPrivateRepoButKeepsItsMetadata(t *testing.T) {
	w := newWorld(t)
	w.cfg.ExposedOnly = true
	priv := w.addRepo("secret-project", core.Private)
	pub := w.addRepo("open-source", core.Public)
	rawPriv, rawPub := fakeKey(t, "sk-", 48), fakeKey(t, "sk-", 48)
	w.plantAll(rawPriv, "openai", core.Unverified)
	w.plantAll(rawPub, "openai", core.Unverified)
	priv.commit("env", map[string]string{".env": "K=" + rawPriv + "\n"})
	pub.commit("env", map[string]string{".env": "K=" + rawPub + "\n"})
	r := w.runner()

	st := mustPoll(t, r)
	if st.Scanned != 1 {
		t.Fatalf("only the public repo should be scanned: %+v", st)
	}
	if n := w.mir.syncCount(w.src("secret-project")); n != 0 {
		t.Fatalf("the private repo's mirror was fetched %d times", n)
	}
	if n := w.mir.syncCount(w.src("open-source")); n != 1 {
		t.Fatalf("the public repo should be fetched once, got %d", n)
	}
	if _, ok := w.store.Get(w.kr.FP(rawPriv)); ok {
		t.Fatal("a secret in a private repo reached the findings")
	}
	if _, ok := w.store.Get(w.kr.FP(rawPub)); !ok {
		t.Fatal("the public repo's secret was not found")
	}
	if !noteMatching(st, "1 private source(s) were listed and left alone") {
		t.Fatalf("the run does not say it left a private repo alone: %v", st.Notes)
	}
	// The snapshot still names both: the hooks look a remote's visibility up in it, and the
	// private repo has to be there to be seen going public.
	snap, _ := loadSnapshot(w.paths.Inventory)
	if snap[w.src("secret-project")].Visibility != core.Private || snap[w.src("open-source")].Visibility != core.Public {
		t.Fatalf("snapshot lost a source's visibility: %+v", snap)
	}

	// Pushing to the private repo, again and again, still fetches nothing.
	w.resetCalls()
	for range 3 {
		priv.commit("more", map[string]string{"x.txt": "x"})
		w.pushed("secret-project")
		mustPoll(t, r)
	}
	if n := w.mir.syncCount(w.src("secret-project")); n != 0 || w.engineCalls() != 0 {
		t.Fatalf("pushes to a private repo caused %d fetches and %d engine runs", n, w.engineCalls())
	}
}

func TestExposedOnlyScansAPrivateRepoTheDayItGoesPublic(t *testing.T) {
	w := newWorld(t)
	w.cfg.ExposedOnly = true
	a := w.addRepo("flipper", core.Private)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Unverified)
	a.commit("old mistake", map[string]string{".env": "K=" + raw + "\n"})
	a.commit("fix", map[string]string{".env": "K=from-the-environment\n"}) // gone from the tip, still in history
	r := w.runner()
	mustPoll(t, r)
	if n := w.mir.syncCount(w.src("flipper")); n != 0 {
		t.Fatalf("fetched while private: %d", n)
	}

	w.inv.edit(w.src("flipper"), func(s *core.Source) { s.Visibility = core.Public })
	w.resetCalls()
	st := mustPoll(t, r)
	if st.Scanned != 1 || w.mir.syncCount(w.src("flipper")) != 1 {
		t.Fatalf("a repo that just went public must be scanned at once: %+v", st)
	}
	for _, e := range w.engines {
		calls := e.callList()
		if len(calls) != 1 || !calls[0].rng.All {
			t.Fatalf("%s: the whole history must be scanned, got %+v", e.name, calls)
		}
	}
	s := w.secret(raw)
	if !s.Exposed() || s.Severity < core.Medium {
		t.Fatalf("a secret in a repo that is now public should be exposed and at least medium: %+v", s)
	}
	if n := noteMatching(st, "private source"); n {
		t.Fatalf("nothing is private any more, yet: %v", st.Notes)
	}
}

func TestExposedOnlyFullRunKeepsThePrivateRepoInTheSnapshot(t *testing.T) {
	w := newWorld(t)
	w.cfg.ExposedOnly = true
	w.addRepo("closed", core.Private).commit("init", map[string]string{"a": "1"})
	w.addRepo("open", core.Public).commit("init", map[string]string{"a": "1"})
	r := w.runner()
	st := mustFull(t, r)
	if st.Scanned != 1 || w.mir.syncCount(w.src("closed")) != 0 {
		t.Fatalf("full run: %+v, private fetched %d times", st, w.mir.syncCount(w.src("closed")))
	}
	snap, _ := loadSnapshot(w.paths.Inventory)
	if len(snap) != 2 {
		t.Fatalf("the snapshot should hold both sources, got %d", len(snap))
	}
	// And the next poll does not ask to scan anything: the private repo is not "never scanned".
	w.resetCalls()
	idle := mustPoll(t, r)
	if idle.Sources != 0 || w.engineCalls() != 0 {
		t.Fatalf("idle poll after a full run: %+v", idle)
	}
	if noteMatching(idle, "no up-to-date scan record") {
		t.Fatalf("a private repo is being counted as unscanned: %v", idle.Notes)
	}
}

func TestExposedOnlyOffByDefaultKeepsScanningEverything(t *testing.T) {
	w := newWorld(t)
	w.addRepo("closed", core.Private).commit("init", map[string]string{"a": "1"})
	r := w.runner()
	if st := mustPoll(t, r); st.Scanned != 1 {
		t.Fatalf("without the scope a private repo is scanned as before: %+v", st)
	}
}

func TestOneRefusesAPrivateSourceUnderTheScope(t *testing.T) {
	w := newWorld(t)
	w.cfg.ExposedOnly = true
	w.addRepo("closed", core.Private).commit("init", map[string]string{"a": "1"})
	r := w.runner()
	mustPoll(t, r)
	_, err := r.One(context.Background(), w.src("closed"), true)
	if err == nil || !strings.Contains(err.Error(), "private") || !strings.Contains(err.Error(), "publish-check") {
		t.Fatalf("a private source must be refused with a pointer to publish-check, got %v", err)
	}
	if n := w.mir.syncCount(w.src("closed")); n != 0 {
		t.Fatalf("it was fetched %d times anyway", n)
	}
}

func TestPublishCheckStillScansAPrivateRepoUnderTheScope(t *testing.T) {
	w := newWorld(t)
	w.cfg.ExposedOnly = true
	a := w.addRepo("about-to-launch", core.Private)
	raw := fakeKey(t, "sk-", 48)
	w.plantAll(raw, "openai", core.Unverified)
	a.commit("oops", map[string]string{".env": "K=" + raw + "\n"})
	r := w.runner()
	res, err := r.PublishCheck(context.Background(), "o/about-to-launch")
	if err != nil {
		t.Fatalf("PublishCheck: %v", err)
	}
	if len(res.Blocking) != 1 {
		t.Fatalf("the check exists to scan what is not public yet, and found %d", len(res.Blocking))
	}
}
