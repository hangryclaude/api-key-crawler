package sweep

import (
	"context"
	"strings"
	"testing"

	"keyguard/internal/core"
)

func repoPaths(w *world, name string) []string {
	var out []string
	for _, e := range w.engines {
		for _, c := range e.callList() {
			if strings.Contains(c.repo, strings.ReplaceAll(w.src(name), "/", "__")) {
				out = append(out, c.repo)
			}
		}
	}
	return out
}

func TestOneScansOnlyThatSourceAndLeavesTheRestAlone(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	b := w.addRepo("b", core.Private)
	rawA, rawB := fakeKey(t, "sk-", 48), fakeKey(t, "sk-", 48)
	w.plantAll(rawA, "openai", core.Unverified)
	w.plantAll(rawB, "openai", core.Unverified)
	a.commit("init", map[string]string{"README": "a\n"})
	b.commit("init", map[string]string{"README": "b\n"})
	r := w.runner()
	mustPoll(t, r) // both are in the snapshot now
	before, _ := loadSnapshot(w.paths.Inventory)

	a.commit("add key", map[string]string{".env": "K=" + rawA + "\n"})
	b.commit("add key", map[string]string{".env": "K=" + rawB + "\n"})
	w.pushed("a")
	w.pushed("b")
	w.resetCalls()
	calls := w.inv.calls

	st, err := r.One(context.Background(), w.src("a"), false)
	if err != nil {
		t.Fatalf("One: %v\n%v", err, st.Notes)
	}
	if st.Kind != "poll" || st.Sources != 1 || st.Scanned != 1 {
		t.Fatalf("stats: %+v", st)
	}
	if w.inv.calls != calls {
		t.Fatalf("One must not touch the inventory (it would consume the events queued for other repos): %+v -> %+v", calls, w.inv.calls)
	}
	if n := len(repoPaths(w, "b")); n != 0 {
		t.Fatalf("the other repo was scanned %d times", n)
	}
	if n := len(repoPaths(w, "a")); n != len(w.engines) {
		t.Fatalf("a was scanned %d times, want once per engine (%d)", n, len(w.engines))
	}
	if _, ok := w.store.Get(w.kr.FP(rawA)); !ok {
		t.Fatal("the key in a was not found")
	}
	if _, ok := w.store.Get(w.kr.FP(rawB)); ok {
		t.Fatal("the key in b was found without b being scanned")
	}

	// The snapshot is untouched: its entry for a is only as new as the snapshot, so the next
	// poll must still see both pushes, find nothing new in a, and scan b.
	after, _ := loadSnapshot(w.paths.Inventory)
	if len(after) != len(before) {
		t.Fatalf("snapshot went from %d to %d sources", len(before), len(after))
	}
	for _, name := range []string{"a", "b"} {
		if after[w.src(name)] != before[w.src(name)] {
			t.Errorf("%s's inventory entry changed: %+v -> %+v", name, before[w.src(name)], after[w.src(name)])
		}
	}
	w.resetCalls()
	next := mustPoll(t, r)
	if next.Sources != 2 || next.Scanned != 1 || next.Skipped != 1 || len(repoPaths(w, "b")) == 0 || len(repoPaths(w, "a")) != 0 {
		t.Fatalf("the following poll should scan b and find nothing new in a: %+v", next)
	}
	if _, ok := w.store.Get(w.kr.FP(rawB)); !ok {
		t.Fatal("the key in b was not found by the following poll")
	}
}

func TestOneFullIgnoresWhatWasScannedBefore(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Private)
	a.commit("init", map[string]string{"README": "a\n"})
	r := w.runner()
	mustPoll(t, r)

	w.resetCalls()
	st, err := r.One(context.Background(), w.src("a"), true)
	if err != nil {
		t.Fatalf("One: %v", err)
	}
	if st.Kind != "full" || st.Scanned != 1 {
		t.Fatalf("stats: %+v", st)
	}
	for _, e := range w.engines {
		calls := e.callList()
		if len(calls) != 1 || !calls[0].rng.All || len(calls[0].rng.Since) != 0 {
			t.Fatalf("%s: a full scan of one source must walk everything, got %+v", e.name, calls)
		}
	}
	w.resetCalls()
	if _, err := r.One(context.Background(), w.src("a"), false); err != nil {
		t.Fatal(err)
	}
	if w.engineCalls() != 0 {
		t.Fatalf("an incremental scan right after a full one found work: %d engine calls", w.engineCalls())
	}
}

func TestOneLooksTheSourceUpOnlyWhenTheSnapshotLacksIt(t *testing.T) {
	w := newWorld(t)
	a := w.addRepo("a", core.Public)
	w.addRepo("b", core.Private)
	a.commit("init", map[string]string{"README": "a\n"})
	r := w.runner()

	st, err := r.One(context.Background(), strings.ToUpper(w.src("a")[:1])+w.src("a")[1:], true) // GitHub ids are case-blind
	if err != nil {
		t.Fatalf("One: %v\n%v", err, st.Notes)
	}
	if w.inv.calls.list != 1 || w.inv.calls.changed != 0 {
		t.Fatalf("expected one List and no Changed, got %+v", w.inv.calls)
	}
	snap, _ := loadSnapshot(w.paths.Inventory)
	if len(snap) != 1 {
		t.Fatalf("only the scanned source belongs in the snapshot, got %d", len(snap))
	}

	st, err = r.One(context.Background(), "github.com/o/missing", false)
	if err == nil || !strings.Contains(err.Error(), "not in the inventory") {
		t.Fatalf("an unknown source must be an error, got %v", err)
	}
	if st.Scanned != 0 {
		t.Fatalf("unknown source scanned something: %+v", st)
	}
}
