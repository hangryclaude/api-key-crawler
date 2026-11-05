package sweep

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"keyguard/internal/core"
	"keyguard/internal/inventory"
	"keyguard/internal/inventory/ghcli"
)

// activityFake is the inventory that names the pages that changed.
type activityFake struct {
	*fakeInventory
	mu   sync.Mutex
	acts []Activity
}

func (a *activityFake) ChangedActivity(ctx context.Context, prev map[string]core.Source) ([]core.Source, []core.Event, []Activity, error) {
	changed, events, err := a.fakeInventory.Changed(ctx, prev)
	a.mu.Lock()
	acts := a.acts
	a.acts = nil // like events, handed out once
	a.mu.Unlock()
	return changed, events, acts, err
}

func (a *activityFake) name(acts ...Activity) {
	a.mu.Lock()
	a.acts = append(a.acts, acts...)
	a.mu.Unlock()
}

func TestPagesTheInventoryNamesAreScannedByExactURLAndEventsAreNotReadTwice(t *testing.T) {
	w := newWorld(t)
	api := &fakeAPI{}
	w.cfg.API = api
	w.cfg.EventURL = nil // the inventory names the pages itself; no event has to carry one
	ai := &activityFake{fakeInventory: w.inv}
	w.cfg.Inventory = ai
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)

	ai.name(
		Activity{Source: w.src("a"), Kind: "issue", URL: "https://github.com/o/a/issues/12", At: "2026-11-03T11:00:00Z"},
		Activity{Source: w.src("a"), Kind: "release", URL: "https://github.com/o/a/releases/tag/v2.0.0", At: "2026-11-03T11:00:01Z"},
		Activity{Source: "github.com/x/y", Kind: "pr", URL: "https://github.com/x/y/pull/3", At: "2026-11-03T11:00:02Z"},
		Activity{Source: w.src("a"), Kind: "issue", URL: "https://github.com/o/a/issues/12", At: "2026-11-03T11:00:03Z"}, // the same page again
	)
	w.inv.events = []core.Event{
		{Source: w.src("a"), Type: "IssuesEvent", At: "2026-11-03T11:00:00Z"},
		{Source: w.src("a"), Type: "ReleaseEvent", At: "2026-11-03T11:00:01Z"},
	}
	st := mustPoll(t, r)
	want := []string{"https://github.com/o/a/issues/12", "https://github.com/o/a/releases/tag/v2.0.0", "https://github.com/x/y/pull/3"}
	if got := api.urls(); !slices.Equal(got, want) {
		t.Fatalf("one scan per named page:\n got %v\nwant %v", got, want)
	}
	if hasNote(st, "named no scannable resource URL") {
		t.Fatalf("the events were folded into the activity and are not unlinked: %v", st.Notes)
	}
	if st.APIResources != 3 {
		t.Fatalf("%+v", st)
	}
	api.reset()
	if mustPoll(t, r); len(api.list()) != 0 {
		t.Fatalf("handed out once, read once: %v", api.urls())
	}
}

func TestAPageTheInventoryNamesThatIsNotThisReposIsDropped(t *testing.T) {
	w := newWorld(t)
	api := &fakeAPI{}
	asked := 0
	w.cfg.API = api
	w.cfg.Token = func(context.Context, string) (string, error) { asked++; return w.token, nil }
	ai := &activityFake{fakeInventory: w.inv}
	w.cfg.Inventory = ai
	w.addRepo("a", core.Private).commit("one", map[string]string{"f": "1\n"})
	r := w.runner()
	mustPoll(t, r)
	ai.name(
		Activity{Source: w.src("a"), Kind: "issue", URL: "https://github.com/someone/else/issues/1"},
		Activity{Source: w.src("a"), Kind: "issue", URL: "https://evil.example/o/a/issues/1"},
		Activity{Source: w.src("a"), Kind: "issue", URL: "https://github.com/o/a/blob/main/.env"},
	)
	st := mustPoll(t, r)
	if len(api.list()) != 0 || asked != 0 || !hasNote(st, "3 issue, pull request or release event(s) named no scannable resource URL") {
		t.Fatalf("%d scans, %d token requests: %v", len(api.list()), asked, st.Notes)
	}
}

func TestAnInventoryWithoutActivityStillReadsEventsWithAnEventURL(t *testing.T) {
	w := newWorld(t)
	api := &fakeAPI{}
	w.cfg.API = api
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})
	r := w.runner() // the plain fake inventory: events only
	mustPoll(t, r)
	w.inv.events = []core.Event{w.event(w.src("a"), "IssuesEvent", "2026-11-03T11:00:00Z", "https://github.com/o/a/issues/5")}
	mustPoll(t, r)
	if got := api.urls(); !slices.Equal(got, []string{"https://github.com/o/a/issues/5"}) {
		t.Fatalf("%v", got)
	}
}

// realShaped has the two methods *inventory.Inventory has beyond core.Inventory, with the
// types it has them in. Standing up the real one needs a whole fake GitHub; the fit is what
// matters here.
type realShaped struct {
	*fakeInventory
	acts []inventory.Activity
	clk  *ghcli.Clock
}

func (r realShaped) Poll(ctx context.Context, prev map[string]core.Source) (inventory.PollResult, error) {
	changed, events, err := r.fakeInventory.Changed(ctx, prev)
	return inventory.PollResult{Changed: changed, Events: events, Activity: r.acts}, err
}

func (r realShaped) Clock() *ghcli.Clock { return r.clk }

func TestTheRealInventorysPollAndClockAreUsedAsTheyAre(t *testing.T) {
	w := newWorld(t)
	api := &fakeAPI{}
	w.cfg.API = api
	github := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	clk := ghcli.NewClock(func() time.Time { return github.Add(2 * time.Hour) }) // this Mac, two hours fast
	clk.Observe(http.Header{"Date": {github.Format(http.TimeFormat)}})
	w.cfg.Now = func() time.Time { return github.Add(2 * time.Hour) }
	w.cfg.Inventory = realShaped{
		fakeInventory: w.inv, clk: clk,
		acts: []inventory.Activity{{Source: w.src("a"), Kind: "issue", URL: "https://github.com/o/a/issues/9", At: "2026-11-03T07:59:00Z"}},
	}
	a := w.addRepo("a", core.Private)
	a.commit("one", map[string]string{"f": "1\n"})

	st := mustPoll(t, w.runner())
	if got := api.urls(); !slices.Equal(got, []string{"https://github.com/o/a/issues/9"}) {
		t.Fatalf("the activity the real inventory's Poll names reaches the scanner: %v", got)
	}
	if st.Finished != github.Format(time.RFC3339) || !hasNote(st, "this Mac's clock is 2h0m0s ahead of GitHub's") {
		t.Fatalf("the real inventory's clock is GitHub's: %+v", st)
	}

	// Before any response has been heard the clock says nothing, and the Mac's stands in.
	cold := realShaped{fakeInventory: w.inv, clk: ghcli.NewClock(func() time.Time { return github })}
	if _, ok := wrapInventory(cold).(Clocked); !ok {
		t.Fatal("the wrapper must offer a clock")
	}
	if _, ok := wrapInventory(cold).(Clocked).ServerNow(); ok {
		t.Fatal("a clock that has heard nothing knows nothing")
	}
}

func TestWrapInventoryLeavesOtherInventoriesAlone(t *testing.T) {
	w := newWorld(t)
	if got := wrapInventory(w.inv); got != core.Inventory(w.inv) {
		t.Fatalf("%T", got)
	}
	ai := &activityFake{fakeInventory: w.inv}
	if got := wrapInventory(ai); got != core.Inventory(ai) {
		t.Fatalf("%T", got)
	}
}
